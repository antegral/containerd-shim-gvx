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

//go:build amd64

package whpx

import "testing"

// rootReg is the register that holds the translation root of the guest.
const rootReg = x64RegCr3

// newRootEnv builds a rootEnv with one processor and one address space.
func newRootEnv(t *testing.T) *rootEnv {
	t.Helper()
	x := newX64Env(t, 1)
	c, ac := x.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rcx, r.Eflags, r.R11 = 0x400000, 0x400000, 0x202, 0x202
	e := &rootEnv{t: t, fb: x.fb, p: x.p, c: c, ac: ac, as: x.as}
	e.stubExit = func(vp *fakeVP, exit []byte) { x.syscall(vp, exit, 0x400000, 0x202, nil) }
	e.stopInReload = func() {
		x.fb.cancelExit = func(buf []byte) { writeCancelExit(buf, 0, x.reload()+0x30) }
	}
	e.install()
	return e
}
