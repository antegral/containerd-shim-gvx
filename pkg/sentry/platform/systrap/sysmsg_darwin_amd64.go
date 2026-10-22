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

//go:build darwin && amd64

package systrap

import (
	"sync/atomic"
	"unsafe"
)

// These constants mirror stub/gvx_stub_amd64.h. The stub reports its own values
// in the hello message and checkHello rejects a stub that disagrees.
const (
	blockSize       = 0x1000
	threadSpan      = 0x10000
	sysmsgSize      = 0x1000
	stubStackBase   = 0x1000
	stubStackTop    = 0x8000
	altStackBase    = 0x8000
	altStackTop     = 0x10000
	sysmsgMagic     = 0x3174737876673031
	helloMagic      = 0x6f6c6c6568767667
	protocolVersion = 2

	stateNew     = 0
	stateTrapped = 2
	stateRun     = 3
	stateCold    = 4
	stateExit    = 5

	kindStart     = 1
	kindSignal    = 3
	kindInterrupt = 4

	cmdFork   = 1
	cmdExit   = 2
	cmdKill   = 3
	cmdThread = 4
	cmdKick   = 5
	cmdJoin   = 6

	layoutWords = 14

	// maxInval is the number of page runs that one resume can pass through mprotect.
	maxInval = 2

	// maxThreadSlots is the number of guest threads of one stub task.
	maxThreadSlots = 4096
)

// ctxState mirrors struct gv_ctx, the Darwin x86_thread_state64_t.
type ctxState struct {
	RAX, RBX, RCX, RDX, RDI, RSI, RBP, RSP uint64
	R8, R9, R10, R11, R12, R13, R14, R15   uint64
	RIP, RFLAGS, CS, FS, GS                uint64
}

// invalRun mirrors struct gv_inval.
type invalRun struct {
	Addr      uint64
	Len       uint64
	TmpProt   uint32
	FinalProt uint32
}

// sysmsg mirrors struct gv_sysmsg. One sysmsg per guest thread lives in memory
// that the Sentry and the stub task share. Every field except State is owned
// by whichever side holds the thread. State is the futex word of the handoff.
type sysmsg struct {
	Magic     uint64
	State     uint32
	Kind      uint32
	Sig       uint64
	Addr      uint64
	Code      uint64
	TrapNo    uint32
	Err       uint32
	Fault     uint64
	GSBase    uint64
	GSApplied uint64
	Cold      uint32
	FPDirty   uint32
	NInval    uint32
	_         uint32
	Inval     [maxInval]invalRun
	TSDBase   uint64
	Ctx       ctxState
	HostSP    uint64
	// FP is the FXSAVE image of the thread.
	FP [512]byte
}

// ctlPage mirrors struct gv_ctl, the command page of the template and of a
// forked stub task.
type ctlPage struct {
	Seq    uint32
	Ack    uint32
	Cmd    uint32
	Result int32
	Cookie uint64
	Arg    uint64
	Arg2   uint64
}

// helloPayload mirrors struct gv_hello.
type helloPayload struct {
	Magic    uint64
	Version  uint32
	Kind     uint32
	Cookie   uint64
	PID      uint64
	CtlAddr  uint64
	PageSize uint64
	Layout   [layoutWords]uint64
}

// expectedLayout lists the layout words in the order that the stub sends them.
func expectedLayout() [layoutWords]uint64 {
	var sm sysmsg
	return [layoutWords]uint64{
		sysmsgSize,
		uint64(unsafe.Offsetof(sm.State)),
		uint64(unsafe.Offsetof(sm.Kind)),
		uint64(unsafe.Offsetof(sm.GSBase)),
		uint64(unsafe.Offsetof(sm.Cold)),
		uint64(unsafe.Offsetof(sm.Inval)),
		uint64(unsafe.Offsetof(sm.Ctx)),
		uint64(unsafe.Offsetof(sm.FP)),
		uint64(unsafe.Sizeof(sm.Ctx)),
		uint64(len(sm.FP)),
		stubStackTop,
		altStackTop,
		uint64(unsafe.Sizeof(ctlPage{})),
		uint64(unsafe.Offsetof(sm.TSDBase)),
	}
}

// loadState reads the handoff word with acquire semantics.
func (sm *sysmsg) loadState() uint32 {
	return atomic.LoadUint32(&sm.State)
}

// storeState publishes the handoff word with release semantics.
func (sm *sysmsg) storeState(v uint32) {
	atomic.StoreUint32(&sm.State, v)
}

func (c *ctlPage) loadAck() uint32 { return atomic.LoadUint32(&c.Ack) }
