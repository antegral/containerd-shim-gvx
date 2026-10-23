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

//go:build (darwin || windows) && amd64

package systrap

import (
	"unsafe"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// winRegs is the register block of an amd64 winSysmsg. The order of the
// general-purpose registers is the order of the CONTEXT record. FsBase holds
// the guest FS base, which the stub loads with WRFSBASE before it returns.
type winRegs struct {
	Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi uint64
	R8, R9, R10, R11, R12, R13, R14, R15   uint64
	Rflags                                 uint64
	FsBase                                 uint64
}

// winSysmsg is the shared page of one guest thread.
type winSysmsg struct {
	winSysmsgHeader
	Regs winRegs
}

// Offsets of the registers in the winSysmsg. A register number is the number
// that an instruction encodes: RAX 0, RCX 1, RDX 2, RBX 3, RSP 4, RBP 5, RSI 6,
// RDI 7, R8 to R15 8 to 15.
const (
	winOffRegBase = winOffRegs
	winOffRflags  = winOffRegs + 16*8
	winOffFsBase  = winOffRflags + 8
)

// winRegOffset returns the offset of general-purpose register n.
func winRegOffset(n int) int { return winOffRegBase + 8*n }

var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs)-winOffRegs]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.Rax)-0]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.Rsp)-4*8]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.R15)-15*8]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.Rflags)-16*8]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.FsBase)-17*8]

const (
	// winSiteLen is the length of the SYSCALL instruction. Its return address
	// is the address of the site plus this length.
	winSiteLen = 2
	// winSlotSize is the size of one trampoline slot. The slot holds the entry
	// code, the relocated instructions, and the jump back.
	winSlotSize = 64
)

// winTrap describes one trap of a thread, as the Sentry decoded it.
type winTrap struct {
	// site is the address of the patched SYSCALL instruction.
	site uint64
	// ret is the address after the SYSCALL, as the hardware leaves it in RCX.
	ret uint64
}

// loadFrom copies the registers of ac into the block.
func (r *winRegs) loadFrom(ac *arch.Context64) {
	g := &ac.StateData().Regs
	r.Rax, r.Rcx, r.Rdx, r.Rbx, r.Rsp, r.Rbp, r.Rsi, r.Rdi = g.Rax, g.Rcx, g.Rdx, g.Rbx, g.Rsp, g.Rbp, g.Rsi, g.Rdi
	r.R8, r.R9, r.R10, r.R11, r.R12, r.R13, r.R14, r.R15 = g.R8, g.R9, g.R10, g.R11, g.R12, g.R13, g.R14, g.R15
	r.Rflags = g.Eflags
	r.FsBase = g.Fs_base
}

// storeTo copies the block into ac the way a SYSCALL leaves the registers: RCX
// holds the return address and R11 holds the flags.
func (r *winRegs) storeTo(ac *arch.Context64, ret uint64) {
	g := &ac.StateData().Regs
	g.Rax, g.Rdx, g.Rbx, g.Rsp, g.Rbp, g.Rsi, g.Rdi = r.Rax, r.Rdx, r.Rbx, r.Rsp, r.Rbp, r.Rsi, r.Rdi
	g.R8, g.R9, g.R10, g.R12, g.R13, g.R14, g.R15 = r.R8, r.R9, r.R10, r.R12, r.R13, r.R14, r.R15
	g.Eflags = r.Rflags
	g.Rip = ret
	g.Rcx = ret
	g.R11 = r.Rflags
	g.Orig_rax = r.Rax
}

// resumeState returns the state that the Sentry publishes for ac after a trap.
// The slot tail runs the relocated instructions and then jumps to the address
// after them, so a resume at another pc uses the cold path.
func (t winTrap) resumeState(ac *arch.Context64) uint32 {
	if ac.StateData().Regs.Rip == t.ret {
		return winStateRunHot
	}
	return winStateRunCold
}

// winSiteReturn returns the address where the guest continues after the site.
func winSiteReturn(site uint64) uint64 { return site + winSiteLen }
