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

//go:build darwin && arm64

package systrap

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/usermem"
)

const probeCalls = 2000

// probeMM is the minimal MemoryManager of Probe. It only records the VMAs
// that the address space reserves for its trampoline islands.
type probeMM struct {
	usermem.IO
	as   platform.AddressSpace
	vmas []hostarch.AddrRange
}

func (m *probeMM) MMap(_ context.Context, opts memmap.MMapOpts) (hostarch.Addr, error) {
	ar := hostarch.AddrRange{Start: opts.Addr, End: opts.Addr + hostarch.Addr(opts.Length)}
	for _, v := range m.vmas {
		if v.Overlaps(ar) {
			return 0, unix.EEXIST
		}
	}
	m.vmas = append(m.vmas, ar)
	return opts.Addr, nil
}

func (m *probeMM) AddressSpace() platform.AddressSpace { return m.as }

func (*probeMM) FindVMAByName(hostarch.AddrRange, string) (hostarch.Addr, uint64, error) {
	return 0, 0, unix.ENOENT
}

// Probe starts the stub, runs a short guest program that makes probeCalls
// system calls, and stops everything. It proves that the stub spawns, that the
// handshake and the handoff work, and how long one round trip takes. Probe
// needs no guest memory manager, so it also runs before any sandbox exists.
func Probe() (ProbeInfo, error) {
	p, err := New()
	if err != nil {
		return ProbeInfo{}, err
	}
	defer p.Close()
	info := ProbeInfo{
		Arch:            runtime.GOARCH,
		PageSize:        int(p.host.hello.PageSize),
		StubPID:         p.host.tmpl.pid,
		ProtocolVersion: p.host.hello.Version,
	}
	as, err := newAddressSpace(p)
	if err != nil {
		return info, err
	}
	defer as.Release()

	const codeAddr, stackAddr = 0x5555_0000_0000, 0x7000_0000_0000
	code, err := p.pool.alloc()
	if err != nil {
		return info, err
	}
	words := []uint32{
		movzW(1, probeCalls), movzW(8, 5),
		arm64SVC0, subsW(1), 0x54ffffc1, // svc; subs x1, x1, #1; b.ne -8
		movzW(8, 6), arm64SVC0,
	}
	for i, w := range words {
		binary.LittleEndian.PutUint32(pageBytes(code)[4*i:], w)
	}
	as.mu.Lock()
	err = as.mapRangeLocked(codeAddr, blockSize, code, hostarch.AccessType{Read: true, Execute: true})
	as.mu.Unlock()
	if err != nil {
		return info, err
	}
	stack, err := p.pool.alloc()
	if err != nil {
		return info, err
	}
	as.mu.Lock()
	err = as.mapRangeLocked(stackAddr, blockSize, stack, hostarch.ReadWrite)
	as.mu.Unlock()
	if err != nil {
		return info, err
	}
	mm := &probeMM{as: as}
	mm.vmas = append(mm.vmas, hostarch.AddrRange{Start: codeAddr, End: codeAddr + blockSize}, hostarch.AddrRange{Start: stackAddr, End: stackAddr + blockSize})
	c := p.NewContext(context.Background()).(*Context)
	defer c.Release()
	ac := arch.New(arch.Host)
	ac.SetIP(codeAddr)
	ac.SetStack(stackAddr + blockSize - 0x100)
	var start time.Time
	for calls := 0; ; calls++ {
		si, _, err := c.Switch(context.Background(), mm, ac, -1)
		if si != nil || err != nil {
			return info, fmt.Errorf("guest probe stopped with signal %v, error %v", si, err)
		}
		switch ac.StateData().Regs.Regs[8] {
		case 5:
			if calls == 1 {
				// The first call patched the page and created the thread, so timing starts after it.
				start = time.Now()
			}
		case 6:
			if calls != probeCalls {
				return info, fmt.Errorf("guest made %d calls, want %d", calls, probeCalls)
			}
			info.RoundTrip = time.Since(start) / (probeCalls - 1)
			return info, nil
		default:
			return info, fmt.Errorf("guest probe made unexpected system call %d", ac.StateData().Regs.Regs[8])
		}
	}
}

func movzW(rd, imm uint32) uint32 { return 0xd2800000 | imm<<5 | rd }
func subsW(rd uint32) uint32      { return 0xf1000400 | rd<<5 | rd }
