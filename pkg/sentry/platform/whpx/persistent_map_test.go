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
	"sync"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// fileOf returns a memmap.File that serves data for the whole range.
func fileOf(data []byte) *fakeFile {
	return &fakeFile{blocks: []safemem.Block{safemem.BlockFromSafeSlice(data)}}
}

// checkWritableEntriesHaveWritableMemory verifies that no page-table entry of
// as grants write access to guest memory that the partition maps read-only.
func checkWritableEntriesHaveWritableMemory(t *testing.T, fb *fakeBackend, as *AddressSpace, va uint64, pages int) {
	t.Helper()
	for i := range pages {
		gpa, opts, _, ok := translate(as, va+uint64(i)*pageSize)
		if !ok || !opts.Write {
			continue
		}
		if mp, _, mapped := fb.mappingOf(gpa); !mapped || mp.flags&mapFlagWrite == 0 {
			t.Errorf("page %d is writable in the page tables but maps read-only memory in the partition", i)
		}
	}
}

func TestMapFileOfFourMiBRegistersHostMemoryOnce(t *testing.T) {
	requireGuestPageSize(t)
	const size = 4 << 20
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := withinOneArena(t, size)
	fr := memmap.FileRange{Start: 0, End: size}

	maps0, unmaps0 := fb.calls()
	if err := as.MapFile(0x400000, fileOf(mem), fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	maps, unmaps := fb.calls()
	// The old design made one call for each of the 1024 pages.
	t.Logf("4 MiB MapFile: %d map calls, %d unmap calls", maps-maps0, unmaps-unmaps0)
	if maps-maps0 != 1 || unmaps != unmaps0 {
		t.Fatalf("MapFile of %d pages made %d map calls and %d unmap calls, want 1 and 0", size/pageSize, maps-maps0, unmaps-unmaps0)
	}
	first, _, _, ok := translate(as, 0x400000)
	if !ok {
		t.Fatal("the first page is not mapped")
	}
	for _, i := range []uint64{1, 511, 512, size/pageSize - 1} {
		gpa, got, user, ok := translate(as, 0x400000+i*pageSize)
		if !ok || !user || !got.Write || gpa != first+i*pageSize {
			t.Fatalf("page %d translates to %#x (mapped %v, %+v), want %#x", i, gpa, ok, got, first+i*pageSize)
		}
		if host, _ := hostOf(fb, gpa); host != unsafe.Pointer(&mem[i*pageSize]) {
			t.Fatalf("page %d maps host %p, want %p", i, host, &mem[i*pageSize])
		}
	}

	// Unmap only clears page-table entries.
	as.Unmap(0x400000, size)
	if maps2, unmaps2 := fb.calls(); maps2 != maps || unmaps2 != unmaps {
		t.Errorf("Unmap of %d pages made %d map calls and %d unmap calls", size/pageSize, maps2-maps, unmaps2-unmaps)
	}
	if _, _, _, ok := translate(as, 0x400000+size/2); ok {
		t.Error("a page stays mapped after Unmap")
	}

	// Mapping the same host range again, at another address or in another
	// address space, makes no call.
	other := newTestAS(t, p)
	for _, target := range []*AddressSpace{as, other} {
		if err := target.MapFile(0x10000000, fileOf(mem), fr, hostarch.ReadWrite, false); err != nil {
			t.Fatal(err)
		}
	}
	if maps3, unmaps3 := fb.calls(); maps3 != maps || unmaps3 != unmaps {
		t.Errorf("remapping made %d map calls and %d unmap calls", maps3-maps, unmaps3-unmaps)
	}
	if g, _, _, _ := translate(other, 0x10000000+size-pageSize); g != first+size-pageSize {
		t.Errorf("the second address space maps the last page at %#x, want %#x", g, first+size-pageSize)
	}
}

func TestMapFileCallsDoNotGrowWithTheRange(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	// One call registers each range, whatever its page count.
	for i, size := range []int{pageSize, 64 * pageSize, 2 << 20, 16 << 20} {
		mem := withinOneArena(t, size)
		maps0, _ := fb.calls()
		fr := memmap.FileRange{Start: 0, End: uint64(size)}
		if err := as.MapFile(hostarch.Addr(0x400000+uint64(i)<<28), fileOf(mem), fr, hostarch.ReadWrite, false); err != nil {
			t.Fatal(err)
		}
		if maps, _ := fb.calls(); maps-maps0 != 1 {
			t.Errorf("MapFile of %d pages made %d map calls, want 1", size/pageSize, maps-maps0)
		}
	}
}

func TestMapFileOfAReadOnlyViewNeverGrantsWrite(t *testing.T) {
	const size = 8 * pageSize
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := withinOneArena(t, size)
	fr := memmap.FileRange{Start: 0, End: size}

	// The first request names no write access, as a read-only host view does.
	if err := as.MapFile(0x400000, fileOf(mem), fr, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	roGPA, _, _, _ := translate(as, 0x400000)
	if mp, _, _ := fb.mappingOf(roGPA); mp.flags&mapFlagWrite != 0 {
		t.Fatalf("a read-only request maps with flags %#x", mp.flags)
	}
	maps0, unmaps0 := fb.calls()

	// A later write request for the same pages registers a writable range
	// for the same host memory. It keeps the read-only range, and the page
	// tables switch to the writable one.
	if err := as.MapFile(0x400000, fileOf(mem), fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	rwGPA, got, _, _ := translate(as, 0x400000)
	if rwGPA == roGPA || !got.Write {
		t.Fatalf("the upgraded entry maps %#x with %+v, want a writable page in a new range", rwGPA, got)
	}
	if maps, unmaps := fb.calls(); maps-maps0 != 1 || unmaps != unmaps0 {
		t.Errorf("the upgrade made %d map calls and %d unmap calls, want 1 and 0", maps-maps0, unmaps-unmaps0)
	}
	if mp, host, ok := fb.mappingOf(roGPA); !ok || mp.flags&mapFlagWrite != 0 || host != unsafe.Pointer(&mem[0]) {
		t.Error("the read-only range changed during the upgrade")
	}
	checkWritableEntriesHaveWritableMemory(t, fb, as, 0x400000, size/pageSize)

	// A read request after the upgrade reuses the writable range.
	if err := as.MapFile(0x800000, fileOf(mem), fr, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	if g, _, _, _ := translate(as, 0x800000); g != rwGPA {
		t.Errorf("a read mapping uses %#x, want the writable range at %#x", g, rwGPA)
	}
	if maps, _ := fb.calls(); maps-maps0 != 1 {
		t.Error("a read mapping of a writable range made a map call")
	}
}

// memoryFileFake is a fakeFile that reports the host size of a memory file.
type memoryFileFake struct {
	*fakeFile
	total uint64
}

func (f memoryFileFake) TotalSize() uint64 { return f.total }

func TestMemoryFileMappedReadOnlyThenWritableRegistersOnce(t *testing.T) {
	const size = 8 * pageSize
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := withinOneArena(t, size)
	file := memoryFileFake{fakeFile: fileOf(mem), total: size}
	fr := memmap.FileRange{Start: 0, End: size}
	maps0, unmaps0 := fb.calls()

	// A fork copy-on-write page starts read-only. The page tables forbid the
	// write, and the partition maps the memory writable, because the memory
	// file owns it with write access.
	if err := as.MapFile(0x400000, file, fr, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	gpa, got, _, ok := translate(as, 0x400000)
	if !ok || got.Write {
		t.Fatalf("the read-only request maps %#x with %+v (mapped %v), want a read-only entry", gpa, got, ok)
	}
	if mp, _, mapped := fb.mappingOf(gpa); !mapped || mp.flags&mapFlagWrite == 0 {
		t.Fatal("the partition maps the memory file read-only, so a later write needs a second range")
	}
	if !file.lastAT.Write {
		t.Error("MapInternal got a read-only access type for a memory file")
	}
	maps1, _ := fb.calls()
	if maps1-maps0 != 1 {
		t.Fatalf("the first request made %d map calls, want 1", maps1-maps0)
	}

	// The write after the copy-on-write break reuses the registered range.
	if err := as.MapFile(0x400000, file, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	rwGPA, got, _, _ := translate(as, 0x400000)
	if rwGPA != gpa || !got.Write {
		t.Fatalf("the write request maps %#x with %+v, want %#x and a writable entry", rwGPA, got, gpa)
	}
	if maps, unmaps := fb.calls(); maps != maps1 || unmaps != unmaps0 {
		t.Errorf("the write request made %d map calls and %d unmap calls, want 0 and 0", maps-maps1, unmaps-unmaps0)
	}
	checkWritableEntriesHaveWritableMemory(t, fb, as, 0x400000, size/pageSize)
}

func TestLargeEntriesSplitOnPartialUnmap(t *testing.T) {
	requireGuestPageSize(t)
	const size = 4 << 20
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)

	// A 2 MiB aligned host range gets a 2 MiB aligned guest physical range,
	// so the page tables can use large entries.
	buf := withinOneArena(t, size+2<<20)
	base := uintptr(unsafe.Pointer(&buf[0]))
	off := int(((base + 2<<20 - 1) &^ (2<<20 - 1)) - base)
	mem := buf[off : off+size : off+size]
	fr := memmap.FileRange{Start: 0, End: size}
	const va = 0x40000000
	if err := as.MapFile(va, fileOf(mem), fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	first, _, _, _ := translate(as, va)
	if _, _, entry, _ := as.pt.Lookup(va, false); entry != 2<<20 {
		t.Fatalf("the page tables use entries of %d bytes, want 2 MiB entries", entry)
	}

	// Remap one page inside the first large entry with fewer permissions.
	// The entry splits, and the call reserved the page-table pages for it.
	if err := as.MapFile(va+7*pageSize, fileOf(mem[7*pageSize:8*pageSize]), memmap.FileRange{Start: 0, End: pageSize}, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	if _, got, _, ok := translate(as, va+7*pageSize); !ok || got.Write {
		t.Errorf("the remapped page is mapped %v with %+v, want read-only", ok, got)
	}

	// Unmap one page inside the second large entry. This split needs
	// reserved page-table pages too.
	hole := uint64(va + 2<<20 + 5*pageSize)
	as.Unmap(hostarch.Addr(hole), pageSize)
	if _, _, _, ok := translate(as, hole); ok {
		t.Error("the unmapped page stays mapped")
	}
	for _, i := range []uint64{0, 6, 8, 511, 512, 512 + 4, 512 + 6, size/pageSize - 1} {
		gpa, got, _, ok := translate(as, va+i*pageSize)
		if !ok || gpa != first+i*pageSize || !got.Write {
			t.Errorf("page %d translates to %#x (mapped %v), want %#x", i, gpa, ok, first+i*pageSize)
		}
	}
	checkWritableEntriesHaveWritableMemory(t, fb, as, va, size/pageSize)
}

func TestConcurrentMapFileRegistersOnce(t *testing.T) {
	const size = 2 << 20
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	mem := withinOneArena(t, size)
	fr := memmap.FileRange{Start: 0, End: size}
	spaces := make([]*AddressSpace, 8)
	for i := range spaces {
		spaces[i] = newTestAS(t, p)
	}
	maps0, _ := fb.calls()

	var wg sync.WaitGroup
	for _, as := range spaces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4 {
				if err := as.MapFile(0x400000, fileOf(mem), fr, hostarch.ReadWrite, false); err != nil {
					t.Error(err)
				}
				as.Unmap(0x400000, size)
			}
			if err := as.MapFile(0x400000, fileOf(mem), fr, hostarch.ReadWrite, false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if maps, _ := fb.calls(); maps-maps0 != 1 {
		t.Errorf("eight address spaces made %d map calls for one host range, want 1", maps-maps0)
	}
	want, _, _, _ := translate(spaces[0], 0x400000)
	for i, as := range spaces {
		if got, _, _, ok := translate(as, 0x400000); !ok || got != want {
			t.Errorf("address space %d maps %#x (mapped %v), want %#x", i, got, ok, want)
		}
	}
}
