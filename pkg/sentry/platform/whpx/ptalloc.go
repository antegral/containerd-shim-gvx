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
	"sync/atomic"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
)

const (
	// ptSlabPages is the number of page-table pages that one slab maps. A
	// slab is 64 KiB, the allocation granularity of Windows.
	ptSlabPages = 16
	ptSlabSize  = ptSlabPages * pageSize
	ptSlabShift = 16
)

// ptSlab is a run of page-table pages with consecutive guest physical
// addresses.
type ptSlab struct {
	mem []byte
	gpa uint64
}

// ptIndex maps host and guest physical addresses to slabs. The pool replaces
// the index when it adds a slab, so readers need no lock.
type ptIndex struct {
	byHost map[uintptr]*ptSlab
	byGPA  map[uint64]*ptSlab
}

// ptPool owns the pages that back guest page tables.
//
// Every page lives at a fixed host address and a fixed guest physical
// address for the life of the partition. The guest page tables hold the
// guest physical addresses, and the pagetables package walks them through
// LookupPTEs.
type ptPool struct {
	be  backend
	gpa *gpaAllocator

	mu    sync.Mutex
	slabs []*ptSlab
	free  []*pagetables.PTEs
	index atomic.Pointer[ptIndex]
}

func newPTPool(be backend, gpa *gpaAllocator) *ptPool {
	p := &ptPool{be: be, gpa: gpa}
	p.index.Store(&ptIndex{byHost: map[uintptr]*ptSlab{}, byGPA: map[uint64]*ptSlab{}})
	return p
}

// grow maps one more slab and adds its pages to the free list.
func (p *ptPool) grow() error {
	mem, err := p.be.allocHost(ptSlabSize)
	if err != nil {
		return fmt.Errorf("whpx: allocate page-table slab: %w", err)
	}
	if uintptr(unsafe.Pointer(&mem[0]))&(ptSlabSize-1) != 0 {
		return errors.Join(fmt.Errorf("whpx: page-table slab is not 64 KiB aligned"), p.be.freeHost(mem))
	}
	gpa, err := p.gpa.allocRunAligned(ptSlabPages, ptSlabPages)
	if err != nil {
		return errors.Join(err, p.be.freeHost(mem))
	}
	if err := p.be.mapGPA(unsafe.Pointer(&mem[0]), gpa, ptSlabSize, partitionFlags(true)&^mapFlagExecute); err != nil {
		return errors.Join(fmt.Errorf("whpx: map page-table slab at %#x: %w", gpa, err), p.be.freeHost(mem))
	}
	slab := &ptSlab{mem: mem, gpa: gpa}
	old := p.index.Load()
	next := &ptIndex{
		byHost: make(map[uintptr]*ptSlab, len(old.byHost)+1),
		byGPA:  make(map[uint64]*ptSlab, len(old.byGPA)+1),
	}
	for k, v := range old.byHost {
		next.byHost[k] = v
	}
	for k, v := range old.byGPA {
		next.byGPA[k] = v
	}
	next.byHost[uintptr(unsafe.Pointer(&mem[0]))>>ptSlabShift] = slab
	next.byGPA[gpa>>ptSlabShift] = slab
	p.index.Store(next)
	p.slabs = append(p.slabs, slab)
	for i := ptSlabPages - 1; i >= 0; i-- {
		p.free = append(p.free, (*pagetables.PTEs)(unsafe.Pointer(&mem[i*pageSize])))
	}
	return nil
}

// take returns a zeroed page-table page.
func (p *ptPool) take() (*pagetables.PTEs, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) == 0 {
		if err := p.grow(); err != nil {
			return nil, err
		}
	}
	n := len(p.free)
	ptes := p.free[n-1]
	p.free = p.free[:n-1]
	return ptes, nil
}

// give returns a page to the pool. The page must be unreachable for every
// virtual processor.
func (p *ptPool) give(ptes *pagetables.PTEs) {
	clear(ptes[:])
	p.mu.Lock()
	p.free = append(p.free, ptes)
	p.mu.Unlock()
}

// physical returns the guest physical address of a pool page.
func (p *ptPool) physical(ptes *pagetables.PTEs) uintptr {
	host := uintptr(unsafe.Pointer(ptes))
	slab := p.index.Load().byHost[host>>ptSlabShift]
	if slab == nil {
		panic(fmt.Sprintf("whpx: page-table page %#x is not in the pool", host))
	}
	return uintptr(slab.gpa) + (host & (ptSlabSize - 1))
}

// lookup returns the pool page at a guest physical address.
func (p *ptPool) lookup(gpa uintptr) *pagetables.PTEs {
	slab := p.index.Load().byGPA[uint64(gpa)>>ptSlabShift]
	if slab == nil {
		panic(fmt.Sprintf("whpx: guest physical address %#x is not a page-table page", gpa))
	}
	return (*pagetables.PTEs)(unsafe.Pointer(&slab.mem[uint64(gpa)&(ptSlabSize-1)]))
}

// release unmaps and frees every slab. The caller guarantees that no virtual
// processor runs.
func (p *ptPool) release() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var errs []error
	for _, s := range p.slabs {
		if err := p.be.unmapGPA(s.gpa, ptSlabSize); err != nil {
			errs = append(errs, fmt.Errorf("whpx: unmap page-table slab %#x: %w", s.gpa, err))
			continue
		}
		if err := p.be.freeHost(s.mem); err != nil {
			errs = append(errs, err)
		}
	}
	p.slabs = nil
	p.free = nil
	p.index.Store(&ptIndex{byHost: map[uintptr]*ptSlab{}, byGPA: map[uint64]*ptSlab{}})
	return errors.Join(errs...)
}

// ptAllocator implements pagetables.Allocator for one set of page tables.
//
// The pagetables package cannot report allocation failures, so callers call
// reserve before every operation that can allocate. A page that the package
// frees waits in quarantine until Recycle. Callers call Recycle only after
// every virtual processor has flushed the old translation. Then the page
// cannot become a table of another address space while a processor walks it.
type ptAllocator struct {
	pool       *ptPool
	ready      []*pagetables.PTEs
	owned      map[*pagetables.PTEs]struct{}
	quarantine []*pagetables.PTEs
}

func newPTAllocator(pool *ptPool) *ptAllocator {
	return &ptAllocator{pool: pool, owned: make(map[*pagetables.PTEs]struct{})}
}

// reserve makes sure that at least n pages are ready for NewPTEs.
func (a *ptAllocator) reserve(n int) error {
	for len(a.ready) < n {
		ptes, err := a.pool.take()
		if err != nil {
			return err
		}
		a.ready = append(a.ready, ptes)
		a.owned[ptes] = struct{}{}
	}
	return nil
}

// NewPTEs implements pagetables.Allocator.NewPTEs.
func (a *ptAllocator) NewPTEs() *pagetables.PTEs {
	n := len(a.ready)
	if n == 0 {
		panic("whpx: page-table allocation without a reservation")
	}
	ptes := a.ready[n-1]
	a.ready = a.ready[:n-1]
	return ptes
}

// PhysicalFor implements pagetables.Allocator.PhysicalFor.
func (a *ptAllocator) PhysicalFor(ptes *pagetables.PTEs) uintptr {
	return a.pool.physical(ptes)
}

// LookupPTEs implements pagetables.Allocator.LookupPTEs.
func (a *ptAllocator) LookupPTEs(physical uintptr) *pagetables.PTEs {
	return a.pool.lookup(physical)
}

// FreePTEs implements pagetables.Allocator.FreePTEs.
func (a *ptAllocator) FreePTEs(ptes *pagetables.PTEs) {
	a.quarantine = append(a.quarantine, ptes)
}

// Recycle implements pagetables.Allocator.Recycle.
func (a *ptAllocator) Recycle() {
	for _, ptes := range a.quarantine {
		clear(ptes[:])
		a.ready = append(a.ready, ptes)
	}
	a.quarantine = a.quarantine[:0]
}

// quarantined returns the number of freed pages that wait for Recycle.
func (a *ptAllocator) quarantined() int { return len(a.quarantine) }

// drain returns every page of the allocator to the pool. The pages must be
// unreachable for every virtual processor.
func (a *ptAllocator) drain() {
	for ptes := range a.owned {
		a.pool.give(ptes)
	}
	clear(a.owned)
	a.ready = nil
	a.quarantine = nil
}

// ptReserveFor returns the number of page-table pages that mapping n
// consecutive pages can allocate at most. The bound counts one table per
// 512 pages plus one per level for a range that straddles a boundary.
func ptReserveFor(n int) int {
	const entries = 512
	pte := n/entries + 2
	pmd := n/(entries*entries) + 2
	pud := n/(entries*entries*entries) + 2
	return pte + pmd + pud + 1
}

var _ pagetables.Allocator = (*ptAllocator)(nil)

// userPageOpts returns the page table options of a user page.
func userPageOpts(at hostarch.AccessType) pagetables.MapOpts {
	return pagetables.MapOpts{AccessType: at, User: true}
}
