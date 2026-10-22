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

package hvf

import "z.gfire.dev/gvx/pkg/hostarch"

func makeTableDescriptor(gpa uint64) uint64 { return x86MakeTableDescriptor(gpa) }

func tableDescriptorIPA(desc uint64) (uint64, bool) { return x86TableDescriptorGPA(desc) }

func userLeafDescriptor(gpa uint64, at hostarch.AccessType) uint64 {
	return x86UserLeafDescriptor(gpa, at)
}
