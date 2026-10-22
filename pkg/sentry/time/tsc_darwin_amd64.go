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

package time

// ReadCounterTicks returns the monotonic clock in nanoseconds. Intel Macs and
// Rosetta 2 publish no TSC frequency that the kernel guarantees, while
// CLOCK_UPTIME_RAW is exact in nanoseconds. The counter and its frequency
// therefore share one domain. Rdtsc still reads the raw TSC for the sampler,
// which measures the TSC rate against the host clock instead of assuming it.
func ReadCounterTicks() uint64 {
	return uint64(MonotonicNanoseconds())
}

// CounterFrequencyHz returns the frequency of ReadCounterTicks, one tick per nanosecond.
func CounterFrequencyHz() uint64 {
	return 1_000_000_000
}
