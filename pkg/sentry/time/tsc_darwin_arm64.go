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

package time

// ReadCounterTicks returns the virtual counter CNTVCT_EL0. It advances at
// CounterFrequencyHz and is the counter that mach_absolute_time reads.
func ReadCounterTicks() uint64 {
	return uint64(Rdtsc())
}

// CounterFrequencyHz returns the CNTFRQ_EL0 frequency of ReadCounterTicks.
func CounterFrequencyHz() uint64 {
	return uint64(getCNTFRQ())
}
