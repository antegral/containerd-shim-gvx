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

import (
	"fmt"
	"unsafe"
)

// The EL1-only mappings (the exception vector page and one CommPage per vCPU)
// live in one process-wide Stage-1 tree installed through TTBR1_EL1. The tree
// is complete before the first vCPU exists and no code changes or frees it
// until the VM ends.
//
// WHY TTBR1: an exception from EL0 runs the vector stub before the stub can
// flush the TLB. If the stub translated its own addresses through the user
// tree (TTBR0_EL1), a released address space could leave stale cached walk
// entries that point at table pages the allocator has since reused. The
// hardware would then fault or, worse, translate through another address
// space's table. The kernel tree is the same for every vCPU and never
// changes, so cached entries for it are always valid. User tables can be
// freed and reused without any leak or any ordering constraint.
const (
	// kernelBaseVA is the first address of the TTBR1 range used by the stub.
	kernelBaseVA uint64 = 0xffff_ff00_0000_0000
	// kernelVectorVA is the VBAR_EL1 value.
	kernelVectorVA = kernelBaseVA
	// kernelCommBaseVA is the address of the CommPage of vCPU 0.
	kernelCommBaseVA = kernelBaseVA + 0x10000
	// kernelCommStride leaves one unmapped guard page after every CommPage.
	kernelCommStride = 2 * pageSize4K
	// kernelCommPages is the CommPage count: one page per possible vCPU.
	kernelCommPages = 64
)

// kernelComm is the CommPage of one vCPU slot.
type kernelComm struct {
	page []byte
	view *CommPage
	ipa  uint64
	va   uint64
}

// kernelMap is the immutable TTBR1 mapping set.
type kernelMap struct {
	tables *tableSet
	comm   []kernelComm
	// prefillRoot is nil: TTBR1_EL1 reaches the kernel tree, so user roots hold
	// no kernel entries.
	prefillRoot func(root []byte)
}

// ttbr1 returns the TTBR1_EL1 value.
func (k *kernelMap) ttbr1() uint64 {
	return k.tables.rootIPA
}

// initKernel builds the TTBR1 tree with one CommPage per vCPU slot. It runs
// before the VM state is visible to other goroutines.
func (v *vmState) initKernel(slots int) error {
	tables, err := newTableSet(v)
	if err != nil {
		return err
	}
	k := &v.kernel
	k.tables = tables
	k.comm = make([]kernelComm, slots)

	vecPage, vecIPA, err := v.allocPage()
	if err != nil {
		return err
	}
	copy(vecPage, buildVectorPage())
	if err := k.mapPage(kernelVectorVA, vecIPA, kernelCode); err != nil {
		return err
	}
	for i := range k.comm {
		page, ipa, err := v.allocPage()
		if err != nil {
			return err
		}
		va := kernelCommBaseVA + uint64(i)*kernelCommStride
		if err := k.mapPage(va, ipa, kernelData); err != nil {
			return err
		}
		k.comm[i] = kernelComm{
			page: page,
			view: (*CommPage)(unsafe.Pointer(unsafe.SliceData(page))),
			ipa:  ipa,
			va:   va,
		}
	}
	return nil
}

func (k *kernelMap) mapPage(va, ipa uint64, kind kernelPageKind) error {
	table, idx, err := k.tables.leafSlot(va, true)
	if err != nil {
		return fmt.Errorf("hvf: build kernel tables: %w", err)
	}
	storePTE(table, idx, kernelLeafDescriptor(ipa, kind))
	return nil
}
