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

// Platform is the darwin/amd64 systrap backend. The amd64 stub does not exist
// yet, so a Platform value never carries state.
type Platform struct {
	platform.Platform
}

// New always fails on darwin/amd64.
//
// The engine here ships an arm64 stub only. An amd64 stub, which Rosetta 2
// would run, needs its own spill code, an XSAVE context layout, a Mach
// thread-state binding and the amd64 patcher. None of these exist in this tree.
//
// A probe on this host showed that a Rosetta task has 4KB VM pages and that the
// resource-exception hand-off that the arm64 stub uses fails in a translated
// child (its mach_msg send returns an error). The bootstrap-port hand-off
// delivered a task port that the probe could not use. The amd64 hand-off and the
// behavior of a Linux `syscall` instruction under Rosetta are therefore unproven.
func New() (*Platform, error) {
	return nil, &ErrUnavailable{
		Host:   "darwin/amd64",
		Reason: "no amd64 stub, patcher or Mach thread-state binding exists: the engine ships the arm64 stub only, and the Rosetta hand-off and syscall behavior are unproven",
	}
}

// Probe always fails on darwin/amd64 for the reason that New gives.
func Probe() (ProbeInfo, error) {
	_, err := New()
	return ProbeInfo{}, err
}
