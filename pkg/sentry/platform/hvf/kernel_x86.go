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

// The Ring-0 image (GDT, IDT, stub code, and one CommPage plus one kernel
// stack per vCPU) lives in a process-wide subtree of the guest page tables. The
// subtree hangs from PML4 entry 511. Every user root links that entry, so the
// stub runs under any CR3. No code changes or frees the subtree until the VM
// ends, which keeps cached walks of it valid: this is the x86 counterpart of
// the TTBR1 tree on ARM64.
const (
	// x86KernelBaseVA is the first address under PML4 entry 511.
	x86KernelBaseVA uint64 = 0xffff_ff80_0000_0000
	x86KernelGDTVA         = x86KernelBaseVA
	x86KernelIDTVA         = x86KernelBaseVA + 0x1000
	x86KernelCodeVA        = x86KernelBaseVA + 0x2000
	// x86KernelCommBaseVA is the CommPage address of vCPU 0.
	x86KernelCommBaseVA = x86KernelBaseVA + 0x10000
	// x86KernelCommStride holds the CommPage, the kernel stack page, and one
	// unmapped guard page below the next CommPage.
	x86KernelCommStride = 3 * pageSize4K
	// x86KernelCommPages is the vCPU slot count.
	x86KernelCommPages = 64

	// x86KernelPML4Slot is the PML4 index of x86KernelBaseVA.
	x86KernelPML4Slot = 511
)

// x86KernelComm is the per-vCPU part of the Ring-0 image.
type x86KernelComm struct {
	page []byte
	view *x86CommPage
	ipa  uint64
	va   uint64

	stack    []byte // The kernel stack page. The interrupt frame sits at its top.
	stackIPA uint64
}

// stackTopVA is the RSP0 value and the SYSCALL stack: the end of the stack page.
func (k *x86KernelComm) stackTopVA() uint64 {
	return k.va + 2*pageSize4K
}

// frameSlotVA is the address the host gives to RSP before the reload routine:
// the vector slot of the interrupt frame.
func (k *x86KernelComm) frameSlotVA() uint64 {
	return k.va + pageSize4K + x86FrameVector
}

// x86KernelMap is the immutable Ring-0 mapping set.
type x86KernelMap struct {
	tables *tableSet
	comm   []x86KernelComm
	// prefillRoot links the kernel PML4 entry into a user root.
	prefillRoot func(root []byte)
	// hltOffset is the page offset of the HLT that ends the spill routine.
	hltOffset int
}

// buildX86KernelMap builds the kernel subtree with one CommPage and one stack
// per vCPU slot. It has no other user until it returns.
func buildX86KernelMap(alloc pageAllocator, slots int) (*x86KernelMap, error) {
	tables, err := newTableSet(alloc)
	if err != nil {
		return nil, err
	}
	k := &x86KernelMap{tables: tables, comm: make([]x86KernelComm, slots)}
	k.prefillRoot = func(root []byte) {
		storePTE(root, x86KernelPML4Slot, loadPTE(tables.root, x86KernelPML4Slot))
	}

	img := buildX86Kernel(x86KernelCodeVA)
	k.hltOffset = img.HLTOffset
	for _, p := range []struct {
		va         uint64
		content    []byte
		kind       string
		executable bool
	}{
		{x86KernelGDTVA, img.GDT, "GDT", false},
		{x86KernelIDTVA, img.IDT, "IDT", false},
		{x86KernelCodeVA, img.Code, "code", true},
	} {
		page, ipa, err := alloc.allocPage()
		if err != nil {
			return nil, err
		}
		copy(page, p.content)
		if err := k.mapPage(p.va, ipa, false, p.executable); err != nil {
			return nil, fmt.Errorf("hvf: map the kernel %s page: %w", p.kind, err)
		}
	}
	for i := range k.comm {
		commPage, commIPA, err := alloc.allocPage()
		if err != nil {
			return nil, err
		}
		stackPage, stackIPA, err := alloc.allocPage()
		if err != nil {
			return nil, err
		}
		va := x86KernelCommBaseVA + uint64(i)*x86KernelCommStride
		if err := k.mapPage(va, commIPA, true, false); err != nil {
			return nil, err
		}
		if err := k.mapPage(va+pageSize4K, stackIPA, true, false); err != nil {
			return nil, err
		}
		kc := x86KernelComm{
			page:     commPage,
			view:     (*x86CommPage)(unsafe.Pointer(unsafe.SliceData(commPage))),
			ipa:      commIPA,
			va:       va,
			stack:    stackPage,
			stackIPA: stackIPA,
		}
		kc.view.Stack = kc.stackTopVA()
		x86FillTSS(kc.view.TSS[:], kc.stackTopVA())
		k.comm[i] = kc
	}
	return k, nil
}

func (k *x86KernelMap) mapPage(va, ipa uint64, writable, executable bool) error {
	table, idx, err := k.tables.leafSlot(va, true)
	if err != nil {
		return fmt.Errorf("hvf: build kernel tables: %w", err)
	}
	storePTE(table, idx, x86KernelLeafDescriptor(ipa, writable, executable))
	return nil
}
