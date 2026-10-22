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
	"bytes"
	"encoding/binary"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
)

// The test builds the x86 kernel subtree with a fake allocator and walks it
// from a user root, as the CPU would after CR3 loads that root.
func TestX86KernelSubtreeIsSharedByEveryUserRoot(t *testing.T) {
	a := newFakeAllocator()
	const slots = 4
	k, err := buildX86KernelMap(a, slots)
	if err != nil {
		t.Fatal(err)
	}
	kernelPages := len(a.live)
	img := buildX86Kernel(x86KernelCodeVA)

	leaf := func(root []byte, va uint64) (uint64, bool) {
		d, ok := walk(a, root, va)
		return d, ok && d != 0
	}
	check := func(name string, root []byte, va uint64, content []byte, writable, executable bool) {
		t.Helper()
		d, ok := leaf(root, va)
		if !ok {
			t.Errorf("%s: %#x is not mapped", name, va)
			return
		}
		if d&x86PTEUser != 0 {
			t.Errorf("%s: descriptor %#x lets user mode in", name, d)
		}
		if (d&x86PTEWritable != 0) != writable || (d&x86PTENX == 0) != executable {
			t.Errorf("%s: descriptor %#x has W=%v X=%v, want W=%v X=%v", name, d, d&x86PTEWritable != 0, d&x86PTENX == 0, writable, executable)
		}
		if content != nil {
			if page := a.live[d&x86PTEAddrMask]; !bytes.Equal(page, content) {
				t.Errorf("%s: the page does not hold the generated image", name)
			}
		}
	}

	for round := range 3 {
		pt, err := NewGuestPageTable(a, k.prefillRoot)
		if err != nil {
			t.Fatal(err)
		}
		root := pt.tables.root
		if got, want := loadPTE(root, x86KernelPML4Slot), loadPTE(k.tables.root, x86KernelPML4Slot); got != want || got == 0 {
			t.Fatalf("round %d: PML4 entry 511 = %#x, want the shared entry %#x", round, got, want)
		}
		check("GDT", root, x86KernelGDTVA, img.GDT, false, false)
		check("IDT", root, x86KernelIDTVA, img.IDT, false, false)
		check("code", root, x86KernelCodeVA, img.Code, false, true)
		for i := range slots {
			va := x86KernelCommBaseVA + uint64(i)*x86KernelCommStride
			check("CommPage", root, va, nil, true, false)
			check("stack", root, va+pageSize4K, nil, true, false)
			if _, ok := leaf(root, va+2*pageSize4K); ok {
				t.Errorf("slot %d: the guard page is mapped", i)
			}
			if k.comm[i].va != va {
				t.Errorf("slot %d: VA %#x, want %#x", i, k.comm[i].va, va)
			}
		}
		// User addresses go through other PML4 entries and never touch the kernel.
		if _, err := pt.MapPage(0x400000, 0x2_0000_0000, hostarch.ReadWrite); err != nil {
			t.Fatal(err)
		}
		if d, _ := leaf(root, 0x400000); d == 0 {
			t.Error("the user mapping vanished")
		}
		pt.markDead()
		pt.release()
		if got := len(a.live); got != kernelPages {
			t.Fatalf("round %d: %d pages are live after release, want the %d kernel pages", round, got, kernelPages)
		}
	}
}

func TestX86KernelSlotsAreDistinctAndInitialized(t *testing.T) {
	a := newFakeAllocator()
	k, err := buildX86KernelMap(a, 8)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint64]bool{}
	for i, kc := range k.comm {
		for _, ipa := range []uint64{kc.ipa, kc.stackIPA} {
			if seen[ipa] {
				t.Fatalf("slot %d reuses the page at %#x", i, ipa)
			}
			seen[ipa] = true
		}
		if kc.view.Stack != kc.stackTopVA() {
			t.Errorf("slot %d: SYSCALL stack %#x, want %#x", i, kc.view.Stack, kc.stackTopVA())
		}
		if got := binary.LittleEndian.Uint64(kc.view.TSS[x86TSSRSP0Offset:]); got != kc.stackTopVA() {
			t.Errorf("slot %d: TSS RSP0 %#x, want %#x", i, got, kc.stackTopVA())
		}
		if got, want := kc.frameSlotVA(), kc.va+pageSize4K+x86FrameVector; got != want {
			t.Errorf("slot %d: frame slot %#x, want %#x", i, got, want)
		}
		// The first push of SYSCALL lands one word below the stack top, which is
		// inside the stack page, not in the guard page.
		if kc.stackTopVA()-8 < kc.va+pageSize4K {
			t.Errorf("slot %d: the stack top is not inside the stack page", i)
		}
	}
	if k.hltOffset <= x86CodeCommon || k.hltOffset >= x86CodeReload {
		t.Errorf("HLT offset %#x is outside the spill routine", k.hltOffset)
	}
	if got := x86KernelCommBaseVA + 64*x86KernelCommStride; got >= x86KernelBaseVA+2<<20 {
		t.Errorf("64 slots reach %#x: beyond the 2MB covered by one page table", got)
	}
}

func TestX86KernelBuildFailsCleanly(t *testing.T) {
	a := newFakeAllocator()
	a.failAt = 6 // Fail inside the first CommPage allocations.
	if _, err := buildX86KernelMap(a, 4); err == nil {
		t.Fatal("buildX86KernelMap hid the allocator failure")
	}
}
