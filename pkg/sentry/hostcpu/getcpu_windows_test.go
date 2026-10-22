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

//go:build windows

package hostcpu

import (
	"runtime"
	"testing"
)

func TestGetCPUStaysBelowCPUCount(t *testing.T) {
	maxCPU, err := MaxPossibleCPU()
	if err != nil {
		t.Fatalf("MaxPossibleCPU: %v", err)
	}
	if want := uint32(runtime.NumCPU() - 1); maxCPU < want {
		t.Fatalf("MaxPossibleCPU = %d, want at least runtime.NumCPU()-1 = %d", maxCPU, want)
	}
	for i := 0; i < 10_000; i++ {
		cpu, err := currentCPU()
		if err != nil {
			t.Fatalf("currentCPU: %v", err)
		}
		if cpu > maxCPU {
			t.Fatalf("currentCPU = %d, want at most %d", cpu, maxCPU)
		}
	}
}

func TestProcessorLayoutIsContiguous(t *testing.T) {
	layout, err := hostLayout()
	if err != nil {
		t.Fatalf("hostLayout: %v", err)
	}
	var next uint32
	for group, first := range layout.firstCPU {
		if first != next {
			t.Fatalf("group %d starts at %d, want %d", group, first, next)
		}
		next += layout.size[group]
	}
	if next != layout.total {
		t.Fatalf("group sizes sum to %d, want total %d", next, layout.total)
	}
}
