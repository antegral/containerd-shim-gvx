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
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

func newTrapContext() *arch.Context64 {
	ac := arch.New(arch.Host)
	r := &ac.StateData().Regs
	r.Rax, r.Rcx, r.Rdx, r.Rbx = 0xA0, 0xA1, 0xA2, 0xA3
	r.Rsp, r.Rbp, r.Rsi, r.Rdi = 0x7000_0000_1000, 0xA5, 0xA6, 0xA7
	r.R8, r.R9, r.R10, r.R11 = 0xB8, 0xB9, 0xBA, 0xBB
	r.R12, r.R13, r.R14, r.R15 = 0xBC, 0xBD, 0xBE, 0xBF
	r.Eflags = 0x246
	r.Rip = 0x5555_0000_0102
	r.Fs_base = 0x7000_0000_2000
	return ac
}

func TestWinRegsFollowTheSyscallInstruction(t *testing.T) {
	src := newTrapContext()
	var r winRegs
	r.loadFrom(src)
	if r.FsBase != src.StateData().Regs.Fs_base {
		t.Errorf("the block holds FS base %#x, want %#x", r.FsBase, src.StateData().Regs.Fs_base)
	}

	dst := arch.New(arch.Host)
	dst.StateData().Regs.Fs_base = 0x1234
	const ret = 0x5555_0000_0102
	r.storeTo(dst, ret)

	want, got := &src.StateData().Regs, &dst.StateData().Regs
	// The hardware leaves the return address in RCX and the flags in R11. The
	// slot clobbers both registers, so storeTo sets them as the instruction does.
	if got.Rcx != ret || got.R11 != want.Eflags || got.Rip != ret {
		t.Errorf("rcx %#x, r11 %#x, rip %#x; want %#x, %#x, %#x", got.Rcx, got.R11, got.Rip, uint64(ret), want.Eflags, uint64(ret))
	}
	for name, pair := range map[string][2]uint64{
		"rax": {got.Rax, want.Rax}, "rdx": {got.Rdx, want.Rdx}, "rbx": {got.Rbx, want.Rbx},
		"rsp": {got.Rsp, want.Rsp}, "rbp": {got.Rbp, want.Rbp}, "rsi": {got.Rsi, want.Rsi}, "rdi": {got.Rdi, want.Rdi},
		"r8": {got.R8, want.R8}, "r9": {got.R9, want.R9}, "r10": {got.R10, want.R10},
		"r12": {got.R12, want.R12}, "r13": {got.R13, want.R13}, "r14": {got.R14, want.R14}, "r15": {got.R15, want.R15},
		"eflags": {got.Eflags, want.Eflags},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %#x after the round trip, want %#x", name, pair[0], pair[1])
		}
	}
	if got.Orig_rax != want.Rax {
		t.Errorf("Orig_rax = %#x, want rax %#x", got.Orig_rax, want.Rax)
	}
	if got.Fs_base != 0x1234 {
		t.Errorf("storeTo changed the FS base to %#x. The Sentry owns it.", got.Fs_base)
	}
}

func TestWinTrapResumesHotOnlyAtTheReturnAddress(t *testing.T) {
	ac := newTrapContext()
	regs := &ac.StateData().Regs
	trap := winTrap{site: regs.Rip - winSiteLen, ret: regs.Rip}
	if got := trap.resumeState(ac); got != winStateRunHot {
		t.Fatalf("an unchanged context resumes with state %d, want RunHot", got)
	}
	// Any register can change on amd64, because the stub loads all of them.
	regs.Rax, regs.Rsp, regs.R15 = 1, 0x7000_0000_0800, 2
	if got := trap.resumeState(ac); got != winStateRunHot {
		t.Errorf("changed registers resume with state %d, want RunHot", got)
	}
	regs.Rip += 1
	if got := trap.resumeState(ac); got != winStateRunCold {
		t.Errorf("a changed program counter resumes with state %d, want RunCold", got)
	}
}

func TestWinSiteReturnIsBehindTheSyscall(t *testing.T) {
	if got := winSiteReturn(0x1000); got != 0x1002 {
		t.Fatalf("the return address of a site at 0x1000 is %#x, want 0x1002", got)
	}
}
