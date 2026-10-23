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

//go:build (darwin || windows) && arm64

package systrap

import (
	"unsafe"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// winRegs is the register block of an arm64 winSysmsg. The stub stores the
// registers of the trapped guest here. X[16] and X[17] hold the guest values,
// which the slot saved below the guest stack pointer.
type winRegs struct {
	X    [31]uint64
	SP   uint64
	NZCV uint64
}

// winSysmsg is the shared page of one guest thread.
type winSysmsg struct {
	winSysmsgHeader
	Regs winRegs
}

// Offsets of the registers in the winSysmsg.
const (
	winOffX    = winOffRegs
	winOffSP   = winOffRegs + 31*8
	winOffNZCV = winOffSP + 8

	// winSlotSize is the size of one trampoline slot.
	winSlotSize = trapSlotSize
	// winSlotTailOffset is the offset of the slot tail. The slot passes its
	// address to the spill routine in x17.
	winSlotTailOffset = trapSlotTailOffset
	// winSiteLen is the length of the patched instruction, and the offset from
	// the site to the instruction that follows it.
	winSiteLen = 4
)

var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs)-winOffRegs]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.SP)-31*8]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.NZCV)-32*8]

// winTrap describes one trap of a thread, as the Sentry decoded it.
type winTrap struct {
	// site is the address of the patched system call instruction.
	site uint64
	// ret is the address where the guest continues after the call.
	ret uint64
	// sp is the guest stack pointer at the trap.
	sp uint64
}

// loadFrom copies the registers of ac into the block.
func (r *winRegs) loadFrom(ac *arch.Context64) {
	regs := &ac.StateData().Regs
	r.X = regs.Regs
	r.SP = regs.Sp
	r.NZCV = regs.Pstate & pstateNZCV
}

// storeTo copies the block into ac. The guest continues at ret.
func (r *winRegs) storeTo(ac *arch.Context64, ret uint64) {
	st := ac.StateData()
	regs := &st.Regs
	regs.Regs = r.X
	regs.Sp = r.SP
	regs.Pc = ret
	regs.Pstate = regs.Pstate&^pstateNZCV | r.NZCV&pstateNZCV
	st.OrigR0 = r.X[0]
}

// resumeState returns the state that the Sentry publishes for ac after a trap.
// The slot tail restores x16 and x17 from the guest stack, and the stub rewrites
// those words. The tail then branches to the instruction after the site, so a
// resume with another pc or another stack uses the cold path.
func (t winTrap) resumeState(ac *arch.Context64) uint32 {
	regs := &ac.StateData().Regs
	if regs.Pc == t.ret && regs.Sp == t.sp {
		return winStateRunHot
	}
	return winStateRunCold
}

// winSiteReturn returns the address where the guest continues after the site.
func winSiteReturn(site uint64) uint64 { return site + winSiteLen }
