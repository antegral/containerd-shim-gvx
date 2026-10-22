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
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
)

// fakeAllocator hands out zeroed heap pages with synthetic guest addresses.
type fakeAllocator struct {
	next   uint64
	live   map[uint64][]byte
	freed  int
	failAt int // Allocation number that fails; zero never fails.
	calls  int
}

func newFakeAllocator() *fakeAllocator {
	return &fakeAllocator{next: 0x1_0000_0000, live: make(map[uint64][]byte)}
}

func (a *fakeAllocator) allocPage() ([]byte, uint64, error) {
	a.calls++
	if a.failAt != 0 && a.calls == a.failAt {
		return nil, 0, errors.New("allocator failure")
	}
	// A 4KB-aligned slice: allocate 8KB and cut at the boundary.
	raw := make([]byte, 2*pageSize4K)
	page := raw[:pageSize4K:pageSize4K]
	ipa := a.next
	a.next += pageSize4K
	a.live[ipa] = page
	return page, ipa, nil
}

func (a *fakeAllocator) freePage(page []byte, ipa uint64) {
	if a.live[ipa] == nil || &a.live[ipa][0] != &page[0] {
		panic("freePage of a page that is not live")
	}
	delete(a.live, ipa)
	a.freed++
}

// walk decodes the leaf descriptor of va through the real table pages.
func walk(a *fakeAllocator, root []byte, va uint64) (uint64, bool) {
	table := root
	for level := uint(0); level < 3; level++ {
		next, ok := tableDescriptorIPA(loadPTE(table, ptIndex(va, level)))
		if !ok {
			return 0, false
		}
		table = a.live[next]
		if table == nil {
			return 0, false
		}
	}
	return loadPTE(table, ptIndex(va, 3)), true
}

func TestGenerationsTrackInvalidationsOnly(t *testing.T) {
	a := newFakeAllocator()
	pt, _ := NewGuestPageTable(a, nil)
	const va = 0x400000
	tlb0, ic0 := pt.generations()

	if inv, _ := pt.MapPage(va, 0x2_0000_0000, hostarch.ReadWrite); inv {
		t.Error("a new mapping reported an invalidation")
	}
	if tlb, ic := pt.generations(); tlb != tlb0 || ic != ic0 {
		t.Errorf("a new data mapping changed the generations: tlb %d->%d ic %d->%d", tlb0, tlb, ic0, ic)
	}
	if inv, _ := pt.MapPage(va, 0x2_0000_0000, hostarch.ReadWrite); inv {
		t.Error("an identical mapping reported an invalidation")
	}
	if inv, _ := pt.MapPage(va, 0x2_0000_4000, hostarch.ReadWrite); !inv {
		t.Error("a new output address did not report an invalidation")
	}
	tlb1, _ := pt.generations()
	if tlb1 != tlb0+1 {
		t.Errorf("TLB generation = %d, want %d", tlb1, tlb0+1)
	}
	if inv, _ := pt.MapPage(va, 0x2_0000_4000, hostarch.Read); !inv {
		t.Error("a permission change did not report an invalidation")
	}

	_, icBefore := pt.generations()
	if _, err := pt.MapPage(va+pageSize4K, 0x2_0000_8000, hostarch.AccessType{Read: true, Execute: true}); err != nil {
		t.Fatal(err)
	}
	if _, ic := pt.generations(); ic != icBefore+1 {
		t.Errorf("an executable mapping moved the instruction-cache generation %d->%d, want +1", icBefore, ic)
	}
	pt.NoteCodeWrite()
	if _, ic := pt.generations(); ic != icBefore+2 {
		t.Errorf("a code write moved the instruction-cache generation to %d, want %d", ic, icBefore+2)
	}

	tlbBefore, _ := pt.generations()
	if !pt.UnmapPage(va) {
		t.Error("UnmapPage of a mapped page reported no invalidation")
	}
	if tlb, _ := pt.generations(); tlb != tlbBefore+1 {
		t.Errorf("unmap moved the TLB generation %d->%d, want +1", tlbBefore, tlb)
	}
	if pt.UnmapPage(va) {
		t.Error("UnmapPage of an unmapped page reported an invalidation")
	}
	if pt.UnmapPage(0x7000_0000_0000) {
		t.Error("UnmapPage of a page without tables reported an invalidation")
	}
	if desc, ok := walk(a, pt.tables.root, va); !ok || desc != 0 {
		t.Errorf("descriptor after unmap = %#x (reached=%v), want 0", desc, ok)
	}
}

func TestReleaseFreesEveryTablePage(t *testing.T) {
	a := newFakeAllocator()
	for round := range 3 {
		pt, err := NewGuestPageTable(a, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Addresses in different level-0, level-1 and level-2 slots.
		for _, va := range []uint64{0x400000, 0x7f00_0000_0000, 0x1234_5678_9000, 0x8000_0000, uint64(round) * 0x20_0000} {
			if _, err := pt.MapPage(va, 0x2_0000_0000, hostarch.ReadWrite); err != nil {
				t.Fatal(err)
			}
		}
		if len(a.live) < 8 {
			t.Fatalf("only %d table pages are live: the test needs distinct paths", len(a.live))
		}
		pt.markDead()
		pt.release()
		if len(a.live) != 0 {
			t.Fatalf("round %d: %d table pages are still live after release", round, len(a.live))
		}
		if _, err := pt.MapPage(0x400000, 0x2_0000_0000, hostarch.Read); !errors.Is(err, errPageTableReleased) {
			t.Errorf("MapPage after release = %v, want errPageTableReleased", err)
		}
		pt.release() // A second release is harmless.
	}
}

func TestTableIDsNeverRepeat(t *testing.T) {
	a := newFakeAllocator()
	seen := make(map[uint64]bool)
	for range 50 {
		pt, err := NewGuestPageTable(a, nil)
		if err != nil {
			t.Fatal(err)
		}
		if seen[pt.id] || pt.id == 0 {
			t.Fatalf("table id %d repeats or is zero", pt.id)
		}
		seen[pt.id] = true
		pt.release()
	}
}

func TestMapPageSurfacesAllocatorFailure(t *testing.T) {
	a := newFakeAllocator()
	pt, err := NewGuestPageTable(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.failAt = a.calls + 2 // Fail while the walk builds the second intermediate table.
	if _, err := pt.MapPage(0x400000, 0x2_0000_0000, hostarch.Read); err == nil {
		t.Fatal("MapPage hid the allocator failure")
	}
	// The tables built so far stay consistent: a later retry works.
	a.failAt = 0
	if _, err := pt.MapPage(0x400000, 0x2_0000_0000, hostarch.Read); err != nil {
		t.Fatalf("MapPage after the failure: %v", err)
	}
	pt.release()
	if len(a.live) != 0 {
		t.Errorf("%d pages leaked after a failed walk", len(a.live))
	}

	failing := newFakeAllocator()
	failing.failAt = 1
	if _, err := NewGuestPageTable(failing, nil); err == nil {
		t.Error("NewGuestPageTable hid the root allocation failure")
	}
}
