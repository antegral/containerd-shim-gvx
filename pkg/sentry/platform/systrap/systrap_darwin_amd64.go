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

import "z.gfire.dev/gvx/pkg/sentry/platform"

// Platform is the darwin/amd64 systrap backend. The project dropped the
// engine, so a Platform value never carries state.
type Platform struct {
	platform.Platform
}

// New always fails on darwin/amd64.
//
// WHY: the only way to run linux/amd64 guests through systrap on macOS is a
// translated stub task under Rosetta 2. A probe showed that the approach works
// in principle: a translated task has 4KB pages, and a Linux `syscall` raises
// SIGSYS. The fail-closed Seatbelt profile that the arm64 stub applies then
// panicked the host kernel, in the sandbox extension at syscallmask.c:259, when
// a translated process applied a syscall-number filter. Without that filter a
// guest could issue host system calls, so the project dropped the engine
// instead of shipping weaker isolation.
func New() (*Platform, error) {
	return nil, &ErrUnavailable{
		Host:   "darwin/amd64",
		Reason: "the project dropped the Rosetta 2 engine: a syscall-number Seatbelt filter on a translated process panicked the host kernel",
	}
}

// Probe always fails on darwin/amd64 for the reason that New gives.
func Probe() (ProbeInfo, error) {
	_, err := New()
	return ProbeInfo{}, err
}
