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

// x86-64 4-level page table descriptor bits.
const (
	x86PTEPresent  uint64 = 1 << 0
	x86PTEWritable uint64 = 1 << 1
	x86PTEUser     uint64 = 1 << 2
	x86PTEAccessed uint64 = 1 << 5
	x86PTEDirty    uint64 = 1 << 6
	x86PTENX       uint64 = 1 << 63
	x86PTEAddrMask uint64 = 0x000ffffffffff000
)

// x86MakeTableDescriptor encodes an entry that points at a lower-level table of
// user mappings. The leaf entries restrict access, so table entries allow
// everything.
func x86MakeTableDescriptor(gpa uint64) uint64 {
	return gpa&x86PTEAddrMask | x86PTEPresent | x86PTEWritable | x86PTEUser
}

// x86MakeKernelTableDescriptor encodes a table entry in the shared kernel
// subtree: supervisor-only, so user code cannot reach any page below it.
func x86MakeKernelTableDescriptor(gpa uint64) uint64 {
	return gpa&x86PTEAddrMask | x86PTEPresent | x86PTEWritable
}

func x86TableDescriptorGPA(desc uint64) (uint64, bool) {
	if desc&x86PTEPresent == 0 {
		return 0, false
	}
	return desc & x86PTEAddrMask, true
}

// x86UserLeafDescriptor encodes a user page. The accessed and dirty bits start
// set so the CPU never writes a descriptor during a walk. Execute-only pages
// stay readable, because x86 has no such mapping.
func x86UserLeafDescriptor(gpa uint64, at hostarch.AccessType) uint64 {
	if !at.Read && !at.Write && !at.Execute {
		return 0
	}
	desc := gpa&x86PTEAddrMask | x86PTEPresent | x86PTEUser | x86PTEAccessed | x86PTEDirty
	if at.Write {
		desc |= x86PTEWritable
	}
	if !at.Execute {
		desc |= x86PTENX
	}
	return desc
}

// x86KernelLeafDescriptor encodes a supervisor-only page.
func x86KernelLeafDescriptor(gpa uint64, writable, executable bool) uint64 {
	desc := gpa&x86PTEAddrMask | x86PTEPresent | x86PTEAccessed | x86PTEDirty
	if writable {
		desc |= x86PTEWritable
	}
	if !executable {
		desc |= x86PTENX
	}
	return desc
}
