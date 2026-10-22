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
	"fmt"
	"sync"
	"unsafe"
)

// errGPAExhausted reports that the guest physical window has no free page.
var errGPAExhausted = errors.New("whpx: guest physical address window is exhausted")

// gpaAllocator hands out 4KB pages of the guest physical window.
//
// Guest physical addresses are independent of guest virtual addresses. Each
// address space translates its own virtual addresses to physical pages, so
// two address spaces never alias each other's memory.
type gpaAllocator struct {
	mu   sync.Mutex
	base uint64
	end  uint64
	next uint64
	free []uint64

	// used has one bit per page from base to next.
	used []uint64
	live int
}

func newGPAAllocator(base, end uint64) *gpaAllocator {
	return &gpaAllocator{base: base, end: end, next: base}
}

func (a *gpaAllocator) bit(gpa uint64) (word int, mask uint64) {
	idx := (gpa - a.base) >> pageShift
	return int(idx >> 6), 1 << (idx & 63)
}

func (a *gpaAllocator) setUsed(gpa uint64) {
	w, m := a.bit(gpa)
	for len(a.used) <= w {
		a.used = append(a.used, 0)
	}
	a.used[w] |= m
	a.live++
}

// allocPage returns one free page. Freed pages are reused before the window
// grows.
func (a *gpaAllocator) allocPage() (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n := len(a.free); n > 0 {
		gpa := a.free[n-1]
		a.free = a.free[:n-1]
		a.setUsed(gpa)
		return gpa, nil
	}
	if a.next+pageSize > a.end {
		return 0, errGPAExhausted
	}
	gpa := a.next
	a.next += pageSize
	a.setUsed(gpa)
	return gpa, nil
}

// allocRunAligned returns pages contiguous pages from the top of the window.
// The first page is a multiple of align pages. The pages that alignment skips
// go to the free list. The run itself never returns to the free list.
func (a *gpaAllocator) allocRunAligned(pages, align int) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	alignBytes := uint64(align) * pageSize
	start := (a.next + alignBytes - 1) &^ (alignBytes - 1)
	size := uint64(pages) * pageSize
	if start+size > a.end {
		return 0, errGPAExhausted
	}
	for gpa := a.next; gpa < start; gpa += pageSize {
		a.free = append(a.free, gpa)
	}
	a.next = start + size
	for off := uint64(0); off < size; off += pageSize {
		a.setUsed(start + off)
	}
	return start, nil
}

// allocRun returns pages contiguous pages from the top of the window.
func (a *gpaAllocator) allocRun(pages int) (uint64, error) {
	return a.allocRunAligned(pages, 1)
}

// freePage returns a page to the allocator. It fails on a page that the
// allocator does not hold, which catches double frees.
func (a *gpaAllocator) freePage(gpa uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if gpa < a.base || gpa >= a.next || gpa&pageMask != 0 {
		return fmt.Errorf("whpx: free of guest physical page %#x outside the allocated window", gpa)
	}
	w, m := a.bit(gpa)
	if w >= len(a.used) || a.used[w]&m == 0 {
		return fmt.Errorf("whpx: free of unallocated guest physical page %#x", gpa)
	}
	a.used[w] &^= m
	a.live--
	a.free = append(a.free, gpa)
	return nil
}

// inUse returns the number of allocated pages.
func (a *gpaAllocator) inUse() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.live
}

// hostPage is one 4KB page of host memory that the partition maps.
type hostPage struct {
	gpa      uint64
	host     uintptr
	data     []byte
	refs     int
	writable bool
}

// memoryMap tracks which host pages the partition maps and at which guest
// physical address.
//
// The key is the host address. Two address spaces that map the same page of
// the Sentry memory file share one guest physical page. A change through one
// mapping shows through the other. The map removes a page from the partition
// when the last mapping releases it. Callers release pages only after the
// guest can no longer reach them.
type memoryMap struct {
	mu    sync.Mutex
	be    backend
	gpa   *gpaAllocator
	pages map[uintptr]*hostPage
}

func newMemoryMap(be backend, gpa *gpaAllocator) *memoryMap {
	return &memoryMap{be: be, gpa: gpa, pages: make(map[uintptr]*hostPage)}
}

// partitionFlags returns the mapping flags of the partition. Execute stays
// on because the guest page tables enforce execute permission.
func partitionFlags(writable bool) uint32 {
	f := mapFlagRead | mapFlagExecute
	if writable {
		f |= mapFlagWrite
	}
	return f
}

// acquire maps data, one page of host memory, and returns its record. A
// second call for the same page adds a reference. writable tells whether the
// host mapping accepts writes.
func (m *memoryMap) acquire(data []byte, writable bool) (*hostPage, error) {
	if len(data) != pageSize {
		return nil, fmt.Errorf("whpx: host slice is %d bytes, want %d", len(data), pageSize)
	}
	host := uintptr(unsafe.Pointer(&data[0]))
	if host&pageMask != 0 {
		return nil, fmt.Errorf("whpx: host address %#x is not page aligned", host)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if hp, ok := m.pages[host]; ok {
		if writable && !hp.writable {
			if err := m.be.mapGPA(unsafe.Pointer(&data[0]), hp.gpa, pageSize, partitionFlags(true)); err != nil {
				return nil, fmt.Errorf("whpx: upgrade mapping of guest page %#x: %w", hp.gpa, err)
			}
			hp.writable = true
		}
		hp.refs++
		return hp, nil
	}
	gpa, err := m.gpa.allocPage()
	if err != nil {
		return nil, err
	}
	if err := m.be.mapGPA(unsafe.Pointer(&data[0]), gpa, pageSize, partitionFlags(writable)); err != nil {
		if ferr := m.gpa.freePage(gpa); ferr != nil {
			err = errors.Join(err, ferr)
		}
		return nil, fmt.Errorf("whpx: map guest page %#x: %w", gpa, err)
	}
	hp := &hostPage{gpa: gpa, host: host, data: data, refs: 1, writable: writable}
	m.pages[host] = hp
	return hp, nil
}

// release drops one reference. When the last reference goes, it removes the
// page from the partition and frees the guest physical page.
func (m *memoryMap) release(hp *hostPage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	hp.refs--
	if hp.refs > 0 {
		return nil
	}
	if hp.refs < 0 {
		return fmt.Errorf("whpx: guest page %#x released more often than acquired", hp.gpa)
	}
	delete(m.pages, hp.host)
	if err := m.be.unmapGPA(hp.gpa, pageSize); err != nil {
		return fmt.Errorf("whpx: unmap guest page %#x: %w", hp.gpa, err)
	}
	return m.gpa.freePage(hp.gpa)
}

// mappedPages returns the number of host pages that the partition maps.
func (m *memoryMap) mappedPages() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pages)
}
