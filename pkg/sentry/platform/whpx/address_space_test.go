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
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// translate returns the guest physical address that the page tables of as
// map for va, and the permissions of the entry.
func translate(as *AddressSpace, va uint64) (gpa uint64, opts hostarch.AccessType, user, ok bool) {
	_, phys, size, o := as.pt.Lookup(hostarch.Addr(va), false)
	if size == 0 {
		return 0, hostarch.AccessType{}, false, false
	}
	return uint64(phys), o.AccessType, o.User, true
}

func TestMapHostBuildsExactPageTableEntries(t *testing.T) {
	requireGuestPageSize(t)
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 3)

	if err := as.mapHost(0x400000, mem[:pageSize], hostarch.AccessType{Read: true, Execute: true}); err != nil {
		t.Fatal(err)
	}
	if err := as.mapHost(0x401000, mem[pageSize:2*pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if err := as.mapHost(0x402000, mem[2*pageSize:], hostarch.Read); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		va   uint64
		want hostarch.AccessType
	}{
		{0x400000, hostarch.AccessType{Read: true, Execute: true}},
		{0x401000, hostarch.ReadWrite},
		{0x402000, hostarch.Read},
	} {
		gpa, got, user, ok := translate(as, c.va)
		if !ok || !user {
			t.Fatalf("page %#x is missing or supervisor-only", c.va)
		}
		if got.Write != c.want.Write || got.Execute != c.want.Execute {
			t.Errorf("page %#x has permissions %+v, want %+v", c.va, got, c.want)
		}
		if _, mapped := fb.mapped[gpa]; !mapped {
			t.Errorf("guest page %#x of %#x is not mapped in the partition", gpa, c.va)
		}
	}
	// Execute-only and write-only requests keep the exact bits.
	if _, _, _, ok := translate(as, 0x403000); ok {
		t.Error("a neighbouring page is mapped")
	}
	// The guest physical address is independent of the virtual address.
	gpa, _, _, _ := translate(as, 0x401000)
	if gpa == 0x401000 {
		t.Error("guest physical address equals the virtual address")
	}
}

func TestTwoAddressSpacesNeverAlias(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	a, b := newTestAS(t, p), newTestAS(t, p)
	if a.rootValue() == b.rootValue() {
		t.Fatal("address spaces share a page-table root")
	}
	memA := mustHost(t, fb, 1)
	memB := mustHost(t, fb, 1)
	// Both map different memory at the same virtual address.
	if err := a.mapHost(0x400000, memA, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if err := b.mapHost(0x400000, memB, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	ga, _, _, _ := translate(a, 0x400000)
	gb, _, _, _ := translate(b, 0x400000)
	if ga == gb {
		t.Fatalf("both address spaces map guest page %#x at 0x400000", ga)
	}
	if fb.mapped[ga].host != unsafe.Pointer(&memA[0]) || fb.mapped[gb].host != unsafe.Pointer(&memB[0]) {
		t.Error("a guest page maps the wrong host memory")
	}

	// Sharing a host page between address spaces shares the guest page.
	if err := b.mapHost(0x500000, memA, hostarch.Read); err != nil {
		t.Fatal(err)
	}
	if gs, _, _, _ := translate(b, 0x500000); gs != ga {
		t.Errorf("shared host page maps to %#x and %#x", gs, ga)
	}
	// Unmapping in one address space keeps the page for the other.
	b.Unmap(0x500000, pageSize)
	if _, ok := fb.mapped[ga]; !ok {
		t.Error("the shared page was unmapped while address space a still uses it")
	}
	a.Unmap(0x400000, pageSize)
	if _, ok := fb.mapped[ga]; ok {
		t.Error("the page stays mapped after its last user unmapped it")
	}
}

func TestCopyInOutEnforcePermissions(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 2)
	if err := as.mapHost(0x400000, mem[:pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if err := as.mapHost(0x401000, mem[pageSize:], hostarch.Read); err != nil {
		t.Fatal(err)
	}

	if n, err := as.CopyOut(0x400ff8, []byte("12345678")); n != 8 || err != nil {
		t.Fatalf("CopyOut returned %d, %v", n, err)
	}
	if string(mem[pageSize-8:pageSize]) != "12345678" {
		t.Error("CopyOut did not reach the host page")
	}
	// A copy that crosses into a read-only page copies the first part and
	// reports the fault address.
	n, err := as.CopyOut(0x400ffc, []byte("abcdefgh"))
	var sf platform.SegmentationFault
	if n != 4 || !errors.As(err, &sf) || sf.Addr != 0x401000 {
		t.Errorf("CopyOut across a permission boundary returned %d, %v", n, err)
	}
	dst := make([]byte, 8)
	if n, err := as.CopyIn(0x400ffc, dst); n != 8 || err != nil || string(dst[:4]) != "abcd" {
		t.Errorf("CopyIn returned %d, %v, %q", n, err, dst)
	}
	if n, err := as.CopyIn(0x401ffc, dst); n != 4 || err == nil {
		t.Errorf("CopyIn past the end returned %d, %v", n, err)
	}
	if z, err := as.ZeroOut(0x400ff0, 16); z != 16 || err != nil {
		t.Errorf("ZeroOut returned %d, %v", z, err)
	} else if mem[pageSize-1] != 0 {
		t.Error("ZeroOut left data behind")
	}
	if z, err := as.ZeroOut(0x400ff0, 0x20); z != 0x10 || err == nil {
		t.Errorf("ZeroOut over a read-only page returned %d, %v", z, err)
	}

	if old, err := as.SwapUint32(0x400100, 7); old != 0 || err != nil {
		t.Errorf("SwapUint32 returned %d, %v", old, err)
	}
	if cur, err := as.CompareAndSwapUint32(0x400100, 6, 9); cur != 7 || err != nil {
		t.Errorf("failed CompareAndSwapUint32 returned %d, %v", cur, err)
	}
	if cur, err := as.CompareAndSwapUint32(0x400100, 7, 9); cur != 7 || err != nil {
		t.Errorf("CompareAndSwapUint32 returned %d, %v", cur, err)
	}
	if v, err := as.LoadUint32(0x400100); v != 9 || err != nil {
		t.Errorf("LoadUint32 returned %d, %v", v, err)
	}
	if _, err := as.SwapUint32(0x401000, 1); err == nil {
		t.Error("SwapUint32 wrote a read-only page")
	}
	if _, err := as.LoadUint32(0x400101); err == nil {
		t.Error("LoadUint32 accepted a misaligned address")
	}
	if _, err := as.LoadUint32(0x600000); err == nil {
		t.Error("LoadUint32 read an unmapped page")
	}
}

func TestMapFileUsesTheRequestedAccessAndRejectsBadHostMemory(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 4)
	fr := memmap.FileRange{Start: 0, End: 2 * pageSize}

	f := &fakeFile{blocks: []safemem.Block{safemem.BlockFromSafeSlice(mem[:2*pageSize])}}
	if err := as.MapFile(0x400000, f, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	if !f.lastAT.Read || !f.lastAT.Write {
		t.Errorf("MapInternal got %+v, want a writable request", f.lastAT)
	}
	for _, va := range []uint64{0x400000, 0x401000} {
		if _, got, _, ok := translate(as, va); !ok || !got.Write {
			t.Errorf("page %#x is not writable", va)
		}
	}

	// A MapInternal failure is an error. There is no silent read-only retry.
	boom := errors.New("host mapping failed")
	g := &fakeFile{err: boom}
	if err := as.MapFile(0x500000, g, fr, hostarch.ReadWrite, false); !errors.Is(err, boom) {
		t.Errorf("MapFile returned %v", err)
	}
	if g.mapCalled != 1 {
		t.Errorf("MapInternal ran %d times", g.mapCalled)
	}
	if _, _, _, ok := translate(as, 0x500000); ok {
		t.Error("a failed MapFile left a mapping")
	}

	// A host slice that is not page aligned fails the whole call. The first
	// block must not stay mapped.
	before := len(fb.mapped)
	bad := &fakeFile{blocks: []safemem.Block{
		safemem.BlockFromSafeSlice(mem[2*pageSize : 3*pageSize]),
		safemem.BlockFromSafeSlice(mem[3*pageSize+8 : 4*pageSize+8-8]),
	}}
	if err := as.MapFile(0x600000, bad, fr, hostarch.Read, false); err == nil {
		t.Fatal("MapFile accepted unaligned host memory")
	}
	if _, _, _, ok := translate(as, 0x600000); ok {
		t.Error("the aligned block of a failed MapFile stays mapped")
	}
	if len(fb.mapped) != before {
		t.Errorf("a failed MapFile leaks %d partition mappings", len(fb.mapped)-before)
	}

	for _, c := range []struct {
		name string
		addr hostarch.Addr
		fr   memmap.FileRange
		at   hostarch.AccessType
	}{
		{"unaligned address", 0x400800, fr, hostarch.Read},
		{"unaligned file range", 0x700000, memmap.FileRange{Start: 8, End: pageSize + 8}, hostarch.Read},
		{"empty range", 0x700000, memmap.FileRange{}, hostarch.Read},
		{"no access", 0x700000, fr, hostarch.NoAccess},
		{"above the user range", hostarch.Addr(p.maxUser()), fr, hostarch.Read},
		{"wrapping range", hostarch.Addr(^uint64(0) &^ pageMask), fr, hostarch.Read},
	} {
		if err := as.MapFile(c.addr, f, c.fr, c.at, false); err == nil {
			t.Errorf("MapFile accepted %s", c.name)
		}
	}
}

func TestMapFileFailureKeepsExistingMappings(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 2)
	if err := as.mapHost(0x400000, mem[:pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	gpa, _, _, _ := translate(as, 0x400000)
	boom := errors.New("partition refused")
	fb.mapErr = func(uint64) error { return boom }
	if err := as.mapHost(0x400000, mem[pageSize:], hostarch.ReadWrite); !errors.Is(err, boom) {
		t.Fatalf("mapHost returned %v", err)
	}
	if got, _, _, ok := translate(as, 0x400000); !ok || got != gpa {
		t.Error("a failed remap changed the existing mapping")
	}
	if n, err := as.CopyOut(0x400000, []byte{1}); n != 1 || err != nil {
		t.Errorf("the old mapping stopped working: %d, %v", n, err)
	}
}

// activeVP simulates a processor that runs guest code for as. It returns the
// processor and a function that makes it leave the guest.
func activeVP(t *testing.T, p *Platform, fb *fakeBackend, as *AddressSpace) (*vcpu, func()) {
	t.Helper()
	v, err := p.acquire(newContext(p))
	if err != nil {
		t.Fatal(err)
	}
	as.addActive(v)
	v.enter()
	return v, func() {
		v.leave()
		as.removeActive(v)
		p.release(v)
	}
}

// waitCancels blocks until the fake received n cancels for the processor.
func waitCancels(fb *fakeBackend, v *vcpu, n int) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	for fb.vps[v.index].cancels < n {
		fb.cond.Wait()
	}
}

func TestUnmapStopsRunningProcessorsBeforeReleasingPages(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 1)
	if err := as.mapHost(0x400000, mem, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	gpa, _, _, _ := translate(as, 0x400000)
	v, leave := activeVP(t, p, fb, as)
	genBefore := as.gen.Load()

	done := make(chan struct{})
	go func() {
		as.Unmap(0x400000, pageSize)
		close(done)
	}()
	waitCancels(fb, v, 1)
	select {
	case <-done:
		t.Fatal("Unmap returned while the processor still ran guest code")
	default:
	}
	fb.mu.Lock()
	_, stillMapped := fb.mapped[gpa]
	fb.mu.Unlock()
	if !stillMapped {
		t.Error("the guest page was unmapped before the processor left the guest")
	}
	if as.gen.Load() == genBefore {
		t.Error("Unmap did not advance the TLB generation")
	}
	leave()
	<-done
	fb.mu.Lock()
	_, stillMapped = fb.mapped[gpa]
	fb.mu.Unlock()
	if stillMapped {
		t.Error("the guest page stays mapped after Unmap")
	}
}

func TestFreedPageTablesWaitForTheInvalidation(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 1)
	if err := as.mapHost(0x40000000, mem, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	v, leave := activeVP(t, p, fb, as)
	done := make(chan struct{})
	go func() {
		// The range covers a whole page table, so the page tables free it.
		as.Unmap(0x40000000, 2<<20)
		close(done)
	}()
	waitCancels(fb, v, 1)
	// The freed table waits in quarantine while the processor may still walk it.
	if q := as.alloc.quarantined(); q == 0 {
		t.Error("no page table is quarantined after the last entry went away")
	}
	leave()
	<-done
	if q := as.alloc.quarantined(); q != 0 {
		t.Errorf("%d page tables stay in quarantine after the invalidation", q)
	}
}

func TestReplacingAMappingInvalidatesAndReleasesTheOldPage(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 2)
	if err := as.mapHost(0x400000, mem[:pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	oldGPA, _, _, _ := translate(as, 0x400000)
	gen := as.gen.Load()
	// Mapping a new address does not invalidate anything.
	if err := as.mapHost(0x500000, mem[pageSize:], hostarch.Read); err != nil {
		t.Fatal(err)
	}
	if as.gen.Load() != gen {
		t.Error("a fresh mapping advanced the generation")
	}
	if err := as.mapHost(0x400000, mem[pageSize:], hostarch.Read); err != nil {
		t.Fatal(err)
	}
	if as.gen.Load() == gen {
		t.Error("replacing a mapping did not advance the generation")
	}
	if _, ok := fb.mapped[oldGPA]; ok {
		t.Error("the replaced page stays mapped in the partition")
	}
	if n, err := as.CopyOut(0x400000, []byte{1}); n != 0 || err == nil {
		t.Error("the replaced page is still writable")
	}
}

func TestExecuteMappingsAdvanceTheCodeGeneration(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 2)
	before := as.execGen.Load()
	if err := as.mapHost(0x400000, mem[:pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if as.execGen.Load() != before {
		t.Error("a data mapping advanced the code generation")
	}
	if err := as.mapHost(0x401000, mem[pageSize:], hostarch.AccessType{Read: true, Execute: true}); err != nil {
		t.Fatal(err)
	}
	if as.execGen.Load() == before {
		t.Error("an executable mapping did not advance the code generation")
	}
}

// pageMappings counts the single-page mappings of the fake. Page-table slabs
// are larger and do not count.
func pageMappings(fb *fakeBackend) int {
	n := 0
	for _, m := range fb.mapped {
		if m.size == pageSize {
			n++
		}
	}
	return n
}

func TestReleaseUnmapsAllMemory(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	baseline := pageMappings(fb)
	as, err := p.NewAddressSpace(platformASOptions)
	if err != nil {
		t.Fatal(err)
	}
	a := as.(*AddressSpace)
	mem := mustHost(t, fb, 4)
	for i := range 4 {
		if err := a.mapHost(hostarch.Addr(0x400000+uint64(i)*0x100000), mem[i*pageSize:(i+1)*pageSize], hostarch.ReadWrite); err != nil {
			t.Fatal(err)
		}
	}
	if got := pageMappings(fb); got != baseline+4 {
		t.Fatalf("%d page mappings, want %d", got, baseline+4)
	}
	pagesUsed := p.gpa.inUse()
	as.Release()
	if got := pageMappings(fb); got != baseline {
		t.Errorf("Release leaves %d guest pages mapped", got-baseline)
	}
	as.Release() // A second Release does nothing.
	if err := a.mapHost(0x400000, mem[:pageSize], hostarch.Read); err == nil {
		t.Error("mapping into a released address space succeeded")
	}
	// The page-table pages return to the pool, so a new address space reuses them.
	b := newTestAS(t, p)
	if p.gpa.inUse() > pagesUsed {
		t.Errorf("the guest physical window grew from %d to %d pages", pagesUsed, p.gpa.inUse())
	}
	if b.id == a.id {
		t.Error("address spaces share an identifier")
	}
	if n, err := a.CopyIn(0x400000, make([]byte, 1)); n != 0 || err == nil {
		t.Error("a released address space still serves reads")
	}
}

func TestUnmapOfLargeSparseRanges(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 2)
	for i := range 2 {
		if err := as.mapHost(hostarch.Addr(0x400000+uint64(i)*(1<<40)), mem[i*pageSize:(i+1)*pageSize], hostarch.ReadWrite); err != nil {
			t.Fatal(err)
		}
	}
	// A range far larger than the map takes the sparse path.
	as.Unmap(0x400000, 1<<45)
	for i := range 2 {
		if _, _, _, ok := translate(as, 0x400000+uint64(i)*(1<<40)); ok {
			t.Errorf("page %d survives a huge Unmap", i)
		}
	}
	// A range past the user limit clamps instead of wrapping.
	as.Unmap(hostarch.Addr(p.maxUser()-pageSize), 1<<50)
}
