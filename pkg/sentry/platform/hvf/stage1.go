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
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
)

// errPageTableReleased reports a mapping request on a released page table.
var errPageTableReleased = errors.New("hvf: page table released")

// pageAllocator supplies the 4KB pages that hold page tables. Stage-2 maps
// every page, so the hardware walker can read it.
type pageAllocator interface {
	// allocPage returns a zeroed page and its guest physical address.
	allocPage() (page []byte, ipa uint64, err error)
	// freePage returns a page to the allocator.
	freePage(page []byte, ipa uint64)
}

// tableAlloc implements pagetables.Allocator over a pageAllocator. The
// pagetables package cannot report an allocation failure, so a caller calls
// reserve before every operation that can allocate. A page that the package
// frees waits in quarantine until recycle. The caller recycles only after every
// vCPU that runs the tables flushed its TLB, because a vCPU can still walk a
// freed table until then.
//
// The hardware walker reads table pages through their guest physical address,
// and the pagetables package reads them through the host address. The
// allocator keeps both and converts.
type tableAlloc struct {
	pages      pageAllocator
	ready      []*pagetables.PTEs
	owned      map[*pagetables.PTEs]uint64 // Every page that the allocator holds, with its address.
	byIPA      map[uint64]*pagetables.PTEs
	quarantine []*pagetables.PTEs
}

func newTableAlloc(pages pageAllocator) *tableAlloc {
	return &tableAlloc{
		pages: pages,
		owned: make(map[*pagetables.PTEs]uint64),
		byIPA: make(map[uint64]*pagetables.PTEs),
	}
}

// take gets one zeroed page from the page allocator.
func (a *tableAlloc) take() (*pagetables.PTEs, error) {
	page, ipa, err := a.pages.allocPage()
	if err != nil {
		return nil, err
	}
	ptes := (*pagetables.PTEs)(unsafe.Pointer(unsafe.SliceData(page)))
	a.owned[ptes] = ipa
	a.byIPA[ipa] = ptes
	return ptes, nil
}

// reserve makes sure that at least n pages are ready for NewPTEs.
func (a *tableAlloc) reserve(n int) error {
	for len(a.ready) < n {
		ptes, err := a.take()
		if err != nil {
			return err
		}
		a.ready = append(a.ready, ptes)
	}
	return nil
}

// NewPTEs implements pagetables.Allocator.NewPTEs. A caller that skipped
// reserve gets a fresh page. When the page allocator fails, the call panics,
// because a walk cannot stop in the middle of an update.
func (a *tableAlloc) NewPTEs() *pagetables.PTEs {
	if len(a.ready) == 0 {
		if err := a.reserve(1); err != nil {
			panic(fmt.Sprintf("hvf: allocate a page-table page: %v", err))
		}
	}
	n := len(a.ready)
	ptes := a.ready[n-1]
	a.ready = a.ready[:n-1]
	return ptes
}

// PhysicalFor implements pagetables.Allocator.PhysicalFor.
func (a *tableAlloc) PhysicalFor(ptes *pagetables.PTEs) uintptr {
	ipa, ok := a.owned[ptes]
	if !ok {
		panic(fmt.Sprintf("hvf: page-table page %p does not belong to the allocator", ptes))
	}
	return uintptr(ipa)
}

// LookupPTEs implements pagetables.Allocator.LookupPTEs.
func (a *tableAlloc) LookupPTEs(physical uintptr) *pagetables.PTEs {
	ptes, ok := a.byIPA[uint64(physical)]
	if !ok {
		panic(fmt.Sprintf("hvf: guest physical address %#x is not a page-table page", physical))
	}
	return ptes
}

// FreePTEs implements pagetables.Allocator.FreePTEs.
func (a *tableAlloc) FreePTEs(ptes *pagetables.PTEs) {
	a.quarantine = append(a.quarantine, ptes)
}

// Recycle implements pagetables.Allocator.Recycle.
func (a *tableAlloc) Recycle() {
	for _, ptes := range a.quarantine {
		clear(ptes[:])
		a.ready = append(a.ready, ptes)
	}
	a.quarantine = a.quarantine[:0]
}

// quarantined returns the number of freed pages that wait for Recycle.
func (a *tableAlloc) quarantined() int { return len(a.quarantine) }

// drain returns every page of the allocator to the page allocator. No vCPU
// may walk the pages.
func (a *tableAlloc) drain() {
	for ptes, ipa := range a.owned {
		a.pages.freePage(unsafe.Slice((*byte)(unsafe.Pointer(ptes)), pageSize4K), ipa)
	}
	clear(a.owned)
	clear(a.byIPA)
	a.ready, a.quarantine = nil, nil
}

// reserveForMap returns the number of table pages that a map of n consecutive
// 4KB pages allocates at most. The bound counts one table per 512 pages plus
// two for a range that straddles a boundary, at each of the three lower levels.
func reserveForMap(n uint64) int {
	const entries = 512
	return int(n/entries+2) + int(n/(entries*entries)+2) + int(n/(entries*entries*entries)+2)
}

// reserveForUnmap is the most pages that Unmap allocates. An unmap splits at
// most one block descriptor at each edge of the range, one for each of the two
// levels below the root.
const reserveForUnmap = 4

// kernelTablePages is the number of table pages that a kernel tree reserves
// before its build. The tree needs its roots, one table for each of the three
// lower levels, and spare pages.
const kernelTablePages = 16

// stage1Tables is the Stage-1 translation tree of one address space, below
// TTBR0_EL1 on arm64 and CR3 on amd64. pkg/ring0/pagetables walks and updates
// the tree. This type adds what the hypervisor needs on top: the table pages
// come from the VM, and every vCPU learns from generation counters when its
// cached state is stale.
//
// The TLB generation increments when a valid descriptor changes or disappears,
// and when the tree frees a table page. The instruction-cache generation
// increments when a range with execute permission appears. A vCPU compares
// both counters with the values it last synchronized, and flushes through the
// stub only on a mismatch.
type stage1Tables struct {
	// id is unique for the life of the process. Tables never share an id, so
	// a vCPU cannot mistake a new table for a released one at the same address.
	id uint64

	mu       sync.Mutex
	pt       *pagetables.PageTables
	alloc    *tableAlloc
	released bool

	tlbGen atomic.Uint64
	icGen  atomic.Uint64
	// dead is set before the tables are freed. A vCPU that sees it must not
	// run the table.
	dead atomic.Bool
}

var nextStage1ID atomic.Uint64

// newStage1Tables creates an empty user tree that shares the kernel mappings
// of kernel. The kernel tree is read only, and the new tree never frees it.
func newStage1Tables(pages pageAllocator, kernel *pagetables.PageTables) (*stage1Tables, error) {
	alloc := newTableAlloc(pages)
	if err := alloc.reserve(2); err != nil {
		alloc.drain()
		return nil, err
	}
	return &stage1Tables{
		id:    nextStage1ID.Add(1),
		pt:    pagetables.NewWithUpper(alloc, kernel, userUpperStart),
		alloc: alloc,
	}, nil
}

// generations returns the TLB and instruction-cache generations.
func (s *stage1Tables) generations() (tlb, ic uint64) {
	return s.tlbGen.Load(), s.icGen.Load()
}

// mapRange maps [va, va+length) to the guest physical range that starts at
// ipa, with the permissions of at. It replaces existing mappings, and it uses
// block descriptors where the addresses allow. It reports whether the call
// invalidated a cached translation: callers must then stop every vCPU that
// runs this tree, and call recycle, before they reuse the old memory.
func (s *stage1Tables) mapRange(va, ipa, length uint64, at hostarch.AccessType) (invalidated bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return false, errPageTableReleased
	}
	if err := s.alloc.reserve(reserveForMap(length / pageSize4K)); err != nil {
		return false, err
	}
	replaced := s.pt.Map(hostarch.Addr(va), uintptr(length), pagetables.MapOpts{AccessType: at, User: true}, uintptr(ipa))
	if at.Execute {
		s.icGen.Add(1)
	}
	return s.noteChange(replaced), nil
}

// unmapRange clears [va, va+length). It skips every table that holds no
// descriptor. It reports whether a valid descriptor existed, with the meaning
// of mapRange.
func (s *stage1Tables) unmapRange(va, length uint64) (invalidated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released || length == 0 {
		return false
	}
	// A failed reserve is not an error here. NewPTEs allocates when it must,
	// and an unmap needs a page only to split a block descriptor.
	_ = s.alloc.reserve(reserveForUnmap)
	return s.noteChange(s.pt.Unmap(hostarch.Addr(va), uintptr(length)))
}

// noteChange advances the TLB generation when a change invalidated a cached
// translation. A freed table page counts: a vCPU can cache a walk through it.
func (s *stage1Tables) noteChange(changed bool) bool {
	if changed || s.alloc.quarantined() > 0 {
		s.tlbGen.Add(1)
		return true
	}
	return false
}

// recycle makes the pages that the tree freed available again. The caller
// first stops every vCPU that can still walk them.
func (s *stage1Tables) recycle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alloc.Recycle()
}

// markDead forbids any further run of the table and bumps the TLB generation,
// so a vCPU that already runs it leaves the guest at its next opportunity.
func (s *stage1Tables) markDead() {
	s.dead.Store(true)
	s.tlbGen.Add(1)
}

// release frees every table page, including the root. No vCPU may run the
// table afterwards.
func (s *stage1Tables) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return
	}
	s.released = true
	s.alloc.drain()
}
