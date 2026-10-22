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

//go:build darwin

package hvf

import (
	"os"
	"testing"
)

// allowNoHypervisorEnv names the variable that lets a test host without
// Hypervisor.framework skip the tests that need a VM. CI runners are virtual
// machines that cannot create a nested VM. A developer machine leaves it unset,
// so a missing entitlement fails the test instead of hiding behind a skip.
const allowNoHypervisorEnv = "GVX_ALLOW_NO_HYPERVISOR"

// requireHypervisor skips a test that calls New itself when the host has no
// hypervisor and the environment allows that. See allowNoHypervisorEnv.
func requireHypervisor(t testing.TB) {
	t.Helper()
	p, err := New()
	if err != nil {
		if os.Getenv(allowNoHypervisorEnv) == "1" {
			t.Skipf("no hypervisor on this host (%s=1): %v", allowNoHypervisorEnv, err)
		}
		t.Fatalf("New failed: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
