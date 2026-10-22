// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package systrap

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

// debugger owns the debug object that receives every fault of every stub
// process. One goroutine, pinned to one OS thread, waits for events and hands
// each exception to the guest thread that raised it.
//
// WHY: Windows runs no user-mode code in the stub when a guest faults or
// executes a trap instruction. The kernel sends the exception to the debug
// object first. The Sentry reads and writes the registers of the thread there,
// so the stub needs no handler, no stack, and no valid x18 or TLS register.
type debugger struct {
	obj windows.Handle

	mu    sync.Mutex
	procs map[uint32]*stubProc

	stop atomic.Bool
	done chan struct{}

	// foreign counts events for processes that the debugger does not know.
	foreign atomic.Uint64
}

// eventSlots is the capacity of the event channel of one guest thread. A
// process stays frozen while one of its exceptions waits for a reply, so a
// thread has at most one event outstanding. The spare slot absorbs a stale
// event that follows a forced stop.
const eventSlots = 2

// traceEvents turns on a log of every stop on standard error. A test sets it
// with GVX_SYSTRAP_TRACE=1 to learn why a guest stopped.
var (
	traceEvents = os.Getenv("GVX_SYSTRAP_TRACE") != ""
	// traceAll also prints the stops of patched traps, which are system calls
	// and the repairs that the engine makes. GVX_SYSTRAP_TRACE=2 sets it.
	traceAll = os.Getenv("GVX_SYSTRAP_TRACE") == "2"
	// traceWatch prints the state of every stub process every three seconds.
	// GVX_SYSTRAP_TRACE=2 and GVX_SYSTRAP_TRACE=3 set it. The value 3 prints
	// nothing else, so it does not change the timing of the guest.
	traceWatch = traceAll || os.Getenv("GVX_SYSTRAP_TRACE") == "3"
)

var (
	traceLines atomic.Int64
	// traceMuted silences the trace while Probe runs, because the probe guest
	// makes thousands of identical stops.
	traceMuted atomic.Bool
)

func tracef(format string, args ...any) {
	limit := int64(400)
	if traceAll {
		limit = 200000
	}
	if traceMuted.Load() || traceLines.Add(1) > limit {
		return
	}
	fmt.Fprintf(os.Stderr, "systrap: "+format+"\n", args...)
}

func newDebugger() (*debugger, error) {
	obj, err := ntCreateDebugObject()
	if err != nil {
		return nil, err
	}
	d := &debugger{obj: obj, procs: make(map[uint32]*stubProc), done: make(chan struct{})}
	go d.run()
	if traceWatch {
		go d.watch()
	}
	return d, nil
}

// watch prints the state of every stub process every three seconds, so that a
// trace of a hung guest shows which thread waits for what. GVX_SYSTRAP_TRACE=2
// and GVX_SYSTRAP_TRACE=3 start it.
func (d *debugger) watch() {
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-d.done:
			return
		case <-tick.C:
			d.dumpState()
		}
	}
}

// dumpState prints one line for each stub process and each thread. A thread
// that runs is suspended for the time that the call reads its registers.
func (d *debugger) dumpState() {
	d.mu.Lock()
	procs := make([]*stubProc, 0, len(d.procs))
	for _, sp := range d.procs {
		procs = append(procs, sp)
	}
	d.mu.Unlock()
	fmt.Fprintf(os.Stderr, "systrap: watch: %d stub processes, %d foreign events\n", len(procs), d.foreign.Load())
	for _, sp := range procs {
		sp.mu.Lock()
		threads := make([]*thread, 0, len(sp.threads))
		for _, th := range sp.threads {
			threads = append(threads, th)
		}
		sp.mu.Unlock()
		fmt.Fprintf(os.Stderr, "systrap: watch: pid %d dead %v dropped %d unknown %d threads %d\n",
			sp.pid, sp.dead.Load(), sp.droppedEvents.Load(), sp.unknownThread.Load(), len(threads))
		for _, th := range threads {
			th.dumpState()
		}
	}
}

func (th *thread) dumpState() {
	if !th.mu.TryLock() {
		fmt.Fprintf(os.Stderr, "systrap: watch:   thread %d busy, pending events %d\n", th.tid, len(th.events))
		return
	}
	defer th.mu.Unlock()
	if th.parked {
		fmt.Fprintf(os.Stderr, "systrap: watch:   thread %d parked, pending events %d\n", th.tid, len(th.events))
		return
	}
	if th.ctx == nil {
		fmt.Fprintf(os.Stderr, "systrap: watch:   thread %d is the initial thread of the stub\n", th.tid)
		return
	}
	if err := ntSuspendThread(th.h); err != nil {
		fmt.Fprintf(os.Stderr, "systrap: watch:   thread %d: suspend: %v\n", th.tid, err)
		return
	}
	defer func() { _ = ntResumeThread(th.h) }()
	if err := th.getContext(th.ctx.gprFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "systrap: watch:   thread %d: get context: %v\n", th.tid, err)
		return
	}
	fmt.Fprintf(os.Stderr, "systrap: watch:   thread %d running, stepping %v, pending events %d, pc %#x sp %#x\n",
		th.tid, th.stepping, len(th.events), th.ctx.pc(), th.ctx.sp())
}

// close stops the pump and closes the debug object. The kernel then kills
// every process that is still attached, because the object kills on close.
func (d *debugger) close() {
	if d.stop.Swap(true) {
		return
	}
	<-d.done
	_ = windows.CloseHandle(d.obj)
}

func (d *debugger) register(sp *stubProc) {
	d.mu.Lock()
	d.procs[sp.pid] = sp
	d.mu.Unlock()
}

func (d *debugger) unregister(pid uint32) {
	d.mu.Lock()
	delete(d.procs, pid)
	d.mu.Unlock()
}

func (d *debugger) lookup(pid uint32) *stubProc {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.procs[pid]
}

// run is the pump loop. It must stay on one OS thread, because the kernel
// ties a pending wait to the thread that issued it.
func (d *debugger) run() {
	runtime.LockOSThread()
	defer close(d.done)
	var rec [debugRecordSize]byte
	for !d.stop.Load() {
		ok, err := ntWaitForDebugEvent(d.obj, 50*time.Millisecond, &rec)
		if err != nil {
			d.failAll(err)
			return
		}
		if !ok {
			continue
		}
		d.dispatch(parseDebugEvent(&rec))
	}
}

// failAll marks every stub dead after the debug object failed.
func (d *debugger) failAll(err error) {
	d.mu.Lock()
	procs := make([]*stubProc, 0, len(d.procs))
	for _, sp := range d.procs {
		procs = append(procs, sp)
	}
	d.mu.Unlock()
	for _, sp := range procs {
		sp.markDead(fmt.Errorf("the debug object failed: %w", err))
	}
}

// dispatch routes one event. Exceptions go to the guest thread. Every other
// state needs no work, and the call continues the process at once.
func (d *debugger) dispatch(ev debugEvent) {
	sp := d.lookup(ev.PID)
	if sp == nil {
		// An event of a process that the engine already released.
		d.foreign.Add(1)
		_ = ntDebugContinue(d.obj, ev.PID, ev.TID, dbgContinue)
		return
	}
	switch ev.State {
	case dbgStateException, dbgStateBreakpoint, dbgStateSingleStep:
		th := sp.thread(ev.TID)
		if th == nil {
			// A thread that the engine did not create raised an exception. This
			// happens only when guest code ran an NT service directly.
			sp.unknownThread.Add(1)
			_ = ntDebugContinue(d.obj, ev.PID, ev.TID, dbgNotHandled)
			return
		}
		select {
		case th.events <- ev:
		default:
			// The thread has an outstanding event already. Continue the new one,
			// because a reply to the old one is still pending.
			sp.droppedEvents.Add(1)
			_ = ntDebugContinue(d.obj, ev.PID, ev.TID, dbgContinue)
		}
	case dbgStateExitProc:
		sp.markDead(fmt.Errorf("the stub process exited"))
		_ = ntDebugContinue(d.obj, ev.PID, ev.TID, dbgContinue)
	default:
		_ = ntDebugContinue(d.obj, ev.PID, ev.TID, dbgContinue)
	}
}

// reply tells the kernel to continue the process after an exception. The
// call also unfreezes the other threads of the process.
func (d *debugger) reply(ev debugEvent) error {
	return ntDebugContinue(d.obj, ev.PID, ev.TID, dbgContinue)
}
