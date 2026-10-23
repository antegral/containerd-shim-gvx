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

package hvf

import (
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// TestUnknownExitResumesUntilTheBound covers the spurious exit that a host
// signal causes inside hv_vcpu_run. The worker enters the guest again until the
// run of unknown exits passes the bound, and then it reports an error.
func TestUnknownExitResumesUntilTheBound(t *testing.T) {
	w := &vcpuWorker{exit: &hvVCPUExit{reason: hvExitReasonUnknown}}
	c, pt, ac := &Context{}, &stage1Tables{}, arch.New(arch.Host)

	for i := 1; i <= maxUnknownExits; i++ {
		done, _, _, err := w.dispatchExit(c, pt, ac)
		if done || err != nil {
			t.Fatalf("unknown exit %d: dispatchExit = (done=%v, err=%v), want a resume", i, done, err)
		}
	}
	done, _, _, err := w.dispatchExit(c, pt, ac)
	if !done || err == nil || !strings.Contains(err.Error(), "consecutive") {
		t.Fatalf("exit %d: dispatchExit = (done=%v, err=%v), want a bounded-run error", maxUnknownExits+1, done, err)
	}
}

// TestUnknownExitCounterResetsOnOtherExits checks that the bound counts a run
// of consecutive unknown exits, so scattered ones never add up to an error.
func TestUnknownExitCounterResetsOnOtherExits(t *testing.T) {
	w := &vcpuWorker{exit: &hvVCPUExit{}}
	c, pt, ac := &Context{}, &stage1Tables{}, arch.New(arch.Host)

	for round := 0; round < 3; round++ {
		w.exit.reason = hvExitReasonUnknown
		for i := 0; i < maxUnknownExits; i++ {
			if done, _, _, err := w.dispatchExit(c, pt, ac); done || err != nil {
				t.Fatalf("round %d, unknown exit %d: (done=%v, err=%v), want a resume", round, i, done, err)
			}
		}
		// A cancellation that needs no action resumes the guest, and it ends the run.
		w.exit.reason = hvExitReasonCanceled
		if done, _, _, err := w.dispatchExit(c, pt, ac); done || err != nil {
			t.Fatalf("round %d: canceled exit = (done=%v, err=%v), want a resume", round, done, err)
		}
	}
}
