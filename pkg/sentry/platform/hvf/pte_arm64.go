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

// ARM64 4KB-granule Stage-1 descriptor fields.
const (
	pteAddrMask uint64 = 0x0000fffffffff000

	pteValid    uint64 = 1 << 0
	pteTable    uint64 = 1 << 1 // Table descriptor at levels 0 to 2.
	ptePage     uint64 = 1 << 1 // Page descriptor at level 3.
	pteAttrIdx0 uint64 = 0 << 2 // MAIR attribute 0: normal write-back memory.
	pteAPEL0    uint64 = 1 << 6 // AP[1]: EL0 can access the page.
	pteAPRO     uint64 = 1 << 7 // AP[2]: the page is read-only.
	pteSHInner  uint64 = 3 << 8
	pteAF       uint64 = 1 << 10
	pteNG       uint64 = 1 << 11 // Non-global: the entry belongs to one address space.
	ptePXN      uint64 = 1 << 53
	pteUXN      uint64 = 1 << 54
)

func makeTableDescriptor(ipa uint64) uint64 {
	return ipa&pteAddrMask | pteValid | pteTable
}

func tableDescriptorIPA(desc uint64) (uint64, bool) {
	if desc&(pteValid|pteTable) != pteValid|pteTable {
		return 0, false
	}
	return desc & pteAddrMask, true
}

// userLeafDescriptor encodes a user page. EL1 never executes user pages (PXN).
// A page without any access yields an invalid descriptor.
func userLeafDescriptor(ipa uint64, at hostarch.AccessType) uint64 {
	if !at.Read && !at.Write && !at.Execute {
		return 0
	}
	desc := ipa&pteAddrMask | pteValid | ptePage | pteAttrIdx0 | pteSHInner | pteAF | pteNG | ptePXN | pteAPEL0
	if !at.Write {
		desc |= pteAPRO
	}
	if !at.Execute {
		desc |= pteUXN
	}
	return desc
}

// kernelPageKind selects the permissions of a TTBR1 page.
type kernelPageKind int

const (
	// kernelCode is EL1 read-only and executable, and EL0 has no access.
	kernelCode kernelPageKind = iota
	// kernelData is EL1 read-write and never executable.
	kernelData
)

// kernelLeafDescriptor encodes a global EL1-only page. The nG bit stays clear,
// so the entry applies to every address space.
func kernelLeafDescriptor(ipa uint64, kind kernelPageKind) uint64 {
	desc := ipa&pteAddrMask | pteValid | ptePage | pteAttrIdx0 | pteSHInner | pteAF | pteUXN
	switch kind {
	case kernelCode:
		desc |= pteAPRO
	case kernelData:
		desc |= ptePXN
	}
	return desc
}
