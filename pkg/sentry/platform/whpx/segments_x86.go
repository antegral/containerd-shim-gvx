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

package whpx

// Attribute words of WHV_X64_SEGMENT_REGISTER. SegmentType uses bits 0 to 3
// and NonSystemSegment uses bit 4. DescriptorPrivilegeLevel uses bits 5 and 6
// and Present uses bit 7. Long, Default and Granularity use bits 13 to 15.
// The values match the descriptors in the guest GDT.
const (
	x64AttrKernelCS64 = 0xA09B
	x64AttrKernelSS   = 0xC093
	x64AttrUserCS64   = 0xA0FB
	x64AttrUserCS32   = 0xC0FB
	x64AttrUserData   = 0xC0F3

	// x64AttrTSS describes a busy 64-bit task state segment.
	x64AttrTSS = 0x008B

	x64SegLimit = 0xFFFFFFFF
)

func x64KernelCSValue() segmentValue {
	return segmentValue{limit: x64SegLimit, selector: x64SelKernelCS, attr: x64AttrKernelCS64}
}

func x64KernelSSValue() segmentValue {
	return segmentValue{limit: x64SegLimit, selector: x64SelKernelSS, attr: x64AttrKernelSS}
}

// x64UserCSValue returns the code segment for a user selector. It reports
// false for a selector that is not in the guest GDT.
func x64UserCSValue(sel uint16) (segmentValue, bool) {
	switch sel {
	case x64SelUserCS:
		return segmentValue{limit: x64SegLimit, selector: sel, attr: x64AttrUserCS64}, true
	case x64SelUserCS32:
		return segmentValue{limit: x64SegLimit, selector: sel, attr: x64AttrUserCS32}, true
	}
	return segmentValue{}, false
}

// x64UserDataValue returns a data segment register with the given base. A
// null selector gives an unusable segment, as Linux user space uses for FS
// and GS. It reports false for a selector that is not in the guest GDT.
func x64UserDataValue(sel uint16, base uint64) (segmentValue, bool) {
	switch sel {
	case 0:
		return segmentValue{base: base, limit: x64SegLimit}, true
	case x64SelUserSS:
		return segmentValue{base: base, limit: x64SegLimit, selector: sel, attr: x64AttrUserData}, true
	}
	return segmentValue{}, false
}

// x64UserFlagsMask lists the RFLAGS bits that the Sentry may set for user
// code: the arithmetic flags, TF, DF, RF and AC. Linux uses the same set.
const x64UserFlagsMask = 0x1 | 0x4 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400 | 0x800 | 0x10000 | 0x40000

// x64UserFlags returns the RFLAGS value for a return to user mode: the
// user-settable bits plus IF and the reserved bit 1.
func x64UserFlags(rflags uint64) uint64 {
	return rflags&x64UserFlagsMask | 0x202
}

// x64UserRIPValid reports whether addr is a canonical lower-half address that
// user code can use as an instruction pointer.
func x64UserRIPValid(addr uint64) bool {
	return addr < maxUserAddrX64
}
