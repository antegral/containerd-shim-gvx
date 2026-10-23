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

// Command gostatic is a static Go program for the acceptance tests of
// executables that link at a fixed address. The Go runtime reads its own image
// at start: the module data, the symbol table, and the stack maps. The program
// exercises goroutines, the garbage collector, stack symbolization,
// preemption by signal, and panic recovery. Its output does not depend on the
// architecture.
package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

func main() {
	fmt.Println("sum", fanIn(8, 1000))
	fmt.Println("gc", collectGarbage())
	fmt.Println("frames", frameNames())
	fmt.Println("preempt", preemptSpinner())
	fmt.Println("recover", recoverPanic())
}

// fanIn adds the numbers 1 to n in each of workers goroutines and sums the
// results over a channel.
func fanIn(workers, n int) int {
	results := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sum := 0
			for i := 1; i <= n; i++ {
				sum += i
			}
			results <- sum
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	total := 0
	for sum := range results {
		total += sum
	}
	return total
}

// collectGarbage allocates 64MB in blocks of 256KB, keeps eight blocks alive,
// and reports "ok" when at least three collections ran.
func collectGarbage() string {
	old := debug.SetGCPercent(10)
	defer debug.SetGCPercent(old)
	var ring [8][]byte
	for i := range 256 {
		block := make([]byte, 256<<10)
		block[0] = byte(i)
		ring[i%len(ring)] = block
	}
	for range 3 {
		runtime.GC()
	}
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	if stats.NumGC < 3 || ring[0][0] != 248 {
		return fmt.Sprintf("numgc=%d first=%d", stats.NumGC, ring[0][0])
	}
	return "ok"
}

// frameNames returns the names of the two innermost frames of its own stack.
func frameNames() string {
	pcs := make([]uintptr, 8)
	n := runtime.Callers(1, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	first, _ := frames.Next()
	second, _ := frames.Next()
	return first.Function + " " + second.Function
}

// preemptSpinner runs a loop without calls on the only processor. The main
// goroutine runs again only when the runtime preempts the loop by signal.
func preemptSpinner() string {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		for !stop.Load() {
		}
		close(done)
	}()
	runtime.Gosched()
	stop.Store(true)
	<-done
	return "ok"
}

// recoverPanic unwinds five frames and returns the panic value.
func recoverPanic() (value string) {
	defer func() { value = fmt.Sprint(recover()) }()
	descend(5)
	return "no panic"
}

func descend(depth int) {
	if depth == 0 {
		panic("boom")
	}
	descend(depth - 1)
}
