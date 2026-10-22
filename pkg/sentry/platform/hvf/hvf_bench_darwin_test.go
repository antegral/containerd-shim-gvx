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

import "testing"

// BenchmarkSwitchSyscall measures one guest SVC round trip through Switch.
// The guest runs SVC and branches back, so every iteration is one exit and
// one entry.
func BenchmarkSwitchSyscall(b *testing.B) {
	plat := newTestPlatform(b)
	g := newGuest(b, plat, insnSVC0, 0x17ffffff) // SVC #0; B .-4
	b.ResetTimer()
	for range b.N {
		sig, _, err := g.switchOnce()
		if err != nil || sig != nil {
			b.Fatalf("Switch = (%v, %v)", sig, err)
		}
	}
}
