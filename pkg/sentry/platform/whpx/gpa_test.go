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

import (
	"errors"
	"testing"
)

func TestGPAAllocatorReusesFreedPages(t *testing.T) {
	a := newGPAAllocator(gpaWindowBase, gpaWindowBase+8*pageSize)
	first, err := a.allocPage()
	if err != nil || first != gpaWindowBase {
		t.Fatalf("first page is %#x, %v", first, err)
	}
	second, _ := a.allocPage()
	if second != first+pageSize {
		t.Errorf("second page is %#x, want %#x", second, first+pageSize)
	}
	if err := a.freePage(first); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.allocPage(); got != first {
		t.Errorf("freed page %#x was not reused, got %#x", first, got)
	}
	if a.inUse() != 2 {
		t.Errorf("%d pages in use, want 2", a.inUse())
	}
}

func TestGPAAllocatorRejectsBadFrees(t *testing.T) {
	a := newGPAAllocator(gpaWindowBase, gpaWindowEnd)
	p, _ := a.allocPage()
	if err := a.freePage(p); err != nil {
		t.Fatal(err)
	}
	if err := a.freePage(p); err == nil {
		t.Error("double free accepted")
	}
	for _, bad := range []uint64{0, gpaWindowBase - pageSize, gpaWindowBase + 100*pageSize, p + 1} {
		if err := a.freePage(bad); err == nil {
			t.Errorf("free of %#x accepted", bad)
		}
	}
}

func TestGPAAllocatorExhaustion(t *testing.T) {
	a := newGPAAllocator(gpaWindowBase, gpaWindowBase+2*pageSize)
	for range 2 {
		if _, err := a.allocPage(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.allocPage(); !errors.Is(err, errGPAExhausted) {
		t.Errorf("allocation past the window returned %v", err)
	}
	if _, err := a.allocRun(1); !errors.Is(err, errGPAExhausted) {
		t.Errorf("run past the window returned %v", err)
	}
}

func TestGPAAllocatorAlignedRuns(t *testing.T) {
	a := newGPAAllocator(gpaWindowBase, gpaWindowEnd)
	if _, err := a.allocPage(); err != nil {
		t.Fatal(err)
	}
	run, err := a.allocRunAligned(16, 16)
	if err != nil {
		t.Fatal(err)
	}
	if run%(16*pageSize) != 0 || run < gpaWindowBase+pageSize {
		t.Errorf("run starts at %#x", run)
	}
	// The skipped pages between the first page and the aligned run stay
	// usable and never overlap the run.
	seen := map[uint64]bool{}
	for {
		p, err := a.allocPage()
		if err != nil {
			t.Fatal(err)
		}
		if p >= run && p < run+16*pageSize {
			t.Fatalf("page %#x overlaps the run", p)
		}
		if seen[p] {
			t.Fatalf("page %#x handed out twice", p)
		}
		seen[p] = true
		if p >= run+16*pageSize {
			break
		}
	}
	if err := a.freePage(run); err != nil {
		t.Errorf("a run page cannot be freed: %v", err)
	}
}

func TestMemoryMapSharesAndReleasesPages(t *testing.T) {
	fb := newFakeBackend()
	m := newMemoryMap(fb, newGPAAllocator(gpaWindowBase, gpaWindowEnd))
	mem, _ := fb.allocHost(ptSlabSize)

	a, err := m.acquire(mem[:pageSize], false)
	if err != nil {
		t.Fatal(err)
	}
	if got := fb.mapped[a.gpa].flags; got != mapFlagRead|mapFlagExecute {
		t.Errorf("read-only page maps with flags %#x", got)
	}
	// A second mapping of the same host page shares the guest page.
	b, err := m.acquire(mem[:pageSize], false)
	if err != nil || b != a || a.refs != 2 {
		t.Fatalf("second acquire returned %p refs=%d err=%v, want the same record", b, a.refs, err)
	}
	// A writable request upgrades the mapping in place.
	if _, err := m.acquire(mem[:pageSize], true); err != nil {
		t.Fatal(err)
	}
	if got := fb.mapped[a.gpa].flags; got != mapFlagRead|mapFlagWrite|mapFlagExecute {
		t.Errorf("upgraded page maps with flags %#x", got)
	}
	other, _ := m.acquire(mem[pageSize:2*pageSize], true)
	if other.gpa == a.gpa {
		t.Error("two host pages share a guest page")
	}
	for range 2 {
		if err := m.release(a); err != nil {
			t.Fatal(err)
		}
		if _, ok := fb.mapped[a.gpa]; !ok {
			t.Fatal("page unmapped while references remain")
		}
	}
	gpa := a.gpa
	if err := m.release(a); err != nil {
		t.Fatal(err)
	}
	if _, ok := fb.mapped[gpa]; ok {
		t.Error("page stays mapped after the last release")
	}
	if err := m.release(a); err == nil {
		t.Error("release past zero accepted")
	}
	if m.mappedPages() != 1 {
		t.Errorf("%d pages mapped, want 1", m.mappedPages())
	}
}

func TestMemoryMapPropagatesBackendErrors(t *testing.T) {
	fb := newFakeBackend()
	gpa := newGPAAllocator(gpaWindowBase, gpaWindowEnd)
	m := newMemoryMap(fb, gpa)
	mem, _ := fb.allocHost(ptSlabSize)

	boom := errors.New("map refused")
	fb.mapErr = func(uint64) error { return boom }
	if _, err := m.acquire(mem[:pageSize], true); !errors.Is(err, boom) {
		t.Fatalf("acquire returned %v, want the backend error", err)
	}
	if gpa.inUse() != 0 || m.mappedPages() != 0 {
		t.Errorf("a failed map leaks %d guest pages and %d records", gpa.inUse(), m.mappedPages())
	}
	fb.mapErr = nil
	hp, err := m.acquire(mem[:pageSize], true)
	if err != nil {
		t.Fatal(err)
	}
	fb.unmapErr = func(uint64) error { return boom }
	if err := m.release(hp); !errors.Is(err, boom) {
		t.Errorf("release returned %v, want the backend error", err)
	}
	// A page that failed to unmap stays allocated, so the guest physical
	// page cannot be handed to another host page while it is still mapped.
	if gpa.inUse() != 1 {
		t.Errorf("guest page freed despite the failed unmap, %d in use", gpa.inUse())
	}
}

func TestMemoryMapRejectsBadSlices(t *testing.T) {
	fb := newFakeBackend()
	m := newMemoryMap(fb, newGPAAllocator(gpaWindowBase, gpaWindowEnd))
	mem, _ := fb.allocHost(ptSlabSize)
	if _, err := m.acquire(mem[:pageSize-1], false); err == nil {
		t.Error("short slice accepted")
	}
	if _, err := m.acquire(mem[1:1+pageSize], false); err == nil {
		t.Error("misaligned slice accepted")
	}
}
