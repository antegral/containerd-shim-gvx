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

//go:build arm64

package whpx

import "testing"

// rootReg is the register that holds the user translation root of the guest.
const rootReg = a64RegTtbr0

// newRootEnv builds a rootEnv with one processor and one address space.
func newRootEnv(t *testing.T) *rootEnv {
	t.Helper()
	x := newA64Env(t, 1)
	c, ac := x.newContext()
	ac.StateData().Regs.Pc = 0x400000
	e := &rootEnv{t: t, fb: x.fb, p: x.p, c: c, ac: ac, as: x.as}
	e.stubExit = func(vp *fakeVP, exit []byte) { x.svc(vp, exit, 4, nil) }
	e.stopInReload = func() {
		x.fb.setReg(0, a64RegPstate, a64PstateKernel)
		x.fb.setReg(0, a64RegPc, x.reload()+8)
	}
	e.install()
	return e
}
