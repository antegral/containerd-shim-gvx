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

package hostcpu

import (
	"runtime"
	"sync"
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
		if got := GetCPU(); got > maxCPU {
			t.Fatalf("GetCPU = %d, want at most %d", got, maxCPU)
		}
	}
}

// TestGetCPUFollowsTheThread runs busy threads in parallel. pthread_cpu_number_np
// reports the CPU of the calling thread, so threads that run at the same time
// must report more than one CPU. The Go P index would not do that for a single thread.
func TestGetCPUFollowsTheThread(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Skip("one CPU cannot show different CPU numbers")
	}
	workers := min(runtime.NumCPU(), 4)
	seen := make([]map[uint32]bool, workers)
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(workers)
	done.Add(workers)
	for w := range workers {
		seen[w] = map[uint32]bool{}
		go func() {
			defer done.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready.Done()
			<-start
			for i := 0; i < 2_000_000; i++ {
				seen[w][GetCPU()] = true
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	all := map[uint32]bool{}
	for _, m := range seen {
		for cpu := range m {
			all[cpu] = true
		}
	}
	if len(all) < 2 {
		t.Fatalf("%d parallel threads reported CPUs %v, want at least two distinct CPUs", workers, all)
	}
}
