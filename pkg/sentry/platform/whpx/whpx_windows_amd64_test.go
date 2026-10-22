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

//go:build windows && amd64

package whpx

import (
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

var (
	// syscall
	guestSyscallCode = []byte{0x0F, 0x05}
	// jmp .
	guestLoopCode = []byte{0xEB, 0xFE}
	// movabs rax, [0x10000000]
	guestFaultCode = []byte{0x48, 0xA1, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00}
)

func setGuestEntry(ac *arch.Context64, pc uintptr) {
	r := &ac.StateData().Regs
	r.Rip = uint64(pc)
	r.Rsp = 0x7FFF0000
	r.Rax = 39
	r.Eflags = 0x202
	r.Rcx, r.R11 = r.Rip, r.Eflags
}

func checkSyscallExit(t *testing.T, ac *arch.Context64) {
	t.Helper()
	r := &ac.StateData().Regs
	if r.Rax != 39 || r.Orig_rax != 39 || r.Rip != guestCodeAddr+2 || r.Rcx != guestCodeAddr+2 {
		t.Errorf("after SYSCALL: rax=%d orig=%d rip=%#x rcx=%#x", r.Rax, r.Orig_rax, r.Rip, r.Rcx)
	}
}
