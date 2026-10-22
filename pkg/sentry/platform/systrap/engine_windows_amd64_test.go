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

package systrap

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
)

// TestFSBaseIsRepairedAfterPreemption runs a loop that reads through %fs for
// long enough that Windows switches the thread out. The switch resets the FS
// base, the next read faults at a low address, and the engine loads the base
// again. The sum proves that no read returned a wrong value.
func TestFSBaseIsRepairedAfterPreemption(t *testing.T) {
	r := newRig(t, newPlatform(t))
	const iterations = 1_500_000_000
	loop := imm64([]byte{0x48, 0xB9}, iterations)                 // mov rcx, iterations
	loop = append(loop, 0x31, 0xDB)                               // xor ebx, ebx
	loop = append(loop, 0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0) // loop: mov rax, fs:[0]
	loop = append(loop, 0x48, 0x01, 0xC3)                         // add rbx, rax
	loop = append(loop, 0x48, 0xFF, 0xC9)                         // dec rcx
	loop = append(loop, 0x75, 0xEF)                               // jnz loop (back 17 bytes)
	r.program(loop, gSyscall(93))
	page := r.mapPage(dataVA, hostarch.ReadWrite)
	store64(page, 7)
	setTLSBase(r.ac, dataVA)
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if got, want := regAcc(r.ac), uint64(7*iterations); got != want {
		t.Errorf("sum = %d, want %d", got, want)
	}
	t.Logf("the engine repaired the FS base %d times", r.as.sp.fsRepairs.Load())
}
