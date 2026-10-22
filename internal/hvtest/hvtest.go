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

// Package hvtest tells tests whether the hardware hypervisor of the host
// starts. A hosted CI runner is a virtual machine and may refuse to create a
// nested VM. A developer machine must never hide that failure behind a skip,
// so a skip needs the explicit opt-in GVX_ALLOW_NO_HYPERVISOR=1.
package hvtest

import (
	"os"
	"testing"
)

// AllowNoHypervisorEnv names the variable that allows a skip.
const AllowNoHypervisorEnv = "GVX_ALLOW_NO_HYPERVISOR"

// Require skips the test when the hypervisor does not start and the
// environment allows that. Otherwise it fails the test.
func Require(t testing.TB) {
	t.Helper()
	err := probe()
	if err == nil {
		return
	}
	if os.Getenv(AllowNoHypervisorEnv) == "1" {
		t.Skipf("no hardware hypervisor on this host (%s=1): %v", AllowNoHypervisorEnv, err)
	}
	t.Fatalf("the hardware hypervisor does not start: %v", err)
}
