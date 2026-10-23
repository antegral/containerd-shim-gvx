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
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// The test builds the x86 kernel subtree with a fake allocator. Then it reads
// the PML4 of a user tree, as the CPU would after CR3 loads that root, and
// checks that the user root links the kernel entry.
func TestX86KernelSubtreeIsSharedByEveryUserRoot(t *testing.T) {
	a := newFakeAllocator()
	const slots = 4
	k, err := buildX86KernelMap(a, slots)
	if err != nil {
		t.Fatal(err)
	}
	kernelPages := len(a.live)
	img := buildX86Kernel(x86KernelCodeVA)

	check := func(name string, va uint64, content []byte, writable, executable bool) {
		t.Helper()
		_, phys, size, opts := k.pt.Lookup(hostarch.Addr(va), false)
		if size == 0 {
			t.Errorf("%s: %#x is not mapped", name, va)
			return
		}
		if opts.User {
			t.Errorf("%s: the page lets user mode in", name)
		}
		if opts.AccessType.Write != writable || opts.AccessType.Execute != executable {
			t.Errorf("%s: the page has W=%v X=%v, want W=%v X=%v", name, opts.AccessType.Write, opts.AccessType.Execute, writable, executable)
		}
		if content != nil {
			if page := a.live[uint64(phys)]; !bytes.Equal(page, content) {
				t.Errorf("%s: the page does not hold the generated image", name)
			}
		}
	}
	check("GDT", x86KernelGDTVA, img.GDT, false, false)
	check("IDT", x86KernelIDTVA, img.IDT, false, false)
	check("code", x86KernelCodeVA, img.Code, false, true)
	for i := range slots {
		va := x86KernelCommBaseVA + uint64(i)*x86KernelCommStride
		check("CommPage", va, nil, true, false)
		check("stack", va+pageSize4K, nil, true, false)
		if _, _, size, _ := k.pt.Lookup(hostarch.Addr(va+2*pageSize4K), false); size != 0 {
			t.Errorf("slot %d: the guard page is mapped", i)
		}
		if k.comm[i].va != va {
			t.Errorf("slot %d: VA %#x, want %#x", i, k.comm[i].va, va)
		}
	}

	kernelRoot := k.alloc.LookupPTEs(uintptr(k.pt.CR3(false, 0)))
	for round := range 3 {
		s := newStage1On(t, a, k.pt)
		root := s.alloc.LookupPTEs(uintptr(s.RootIPA()))
		if got, want := root[x86KernelPML4Slot], kernelRoot[x86KernelPML4Slot]; got != want || got == 0 {
			t.Fatalf("round %d: PML4 entry 511 = %#x, want the shared entry %#x", round, got, want)
		}
		// User addresses go through other PML4 entries and never touch the kernel.
		if _, err := s.mapRange(0x400000, 0x2_0000_0000, pageSize4K, hostarch.ReadWrite); err != nil {
			t.Fatal(err)
		}
		if got, size, _ := translate(s, 0x400000); size == 0 || got != 0x2_0000_0000 {
			t.Error("the user mapping vanished")
		}
		if root[x86KernelPML4Slot] != kernelRoot[x86KernelPML4Slot] {
			t.Error("a user mapping changed the shared kernel entry")
		}
		s.markDead()
		s.release()
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
		if got := binary.LittleEndian.Uint64(kc.view.TSS[hvcommon.TSSRSP0Offset:]); got != kc.stackTopVA() {
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
	// The build reserves its table pages first, then it allocates the images.
	// A failure in either step must reach the caller.
	for _, failAt := range []int{2, kernelTablePages + 1, kernelTablePages + 6} {
		a := newFakeAllocator()
		a.failAt = failAt
		if _, err := buildX86KernelMap(a, 4); err == nil {
			t.Fatalf("failAt %d: buildX86KernelMap hid the allocator failure", failAt)
		}
	}
}
