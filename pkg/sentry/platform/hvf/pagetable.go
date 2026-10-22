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
	"sync"
	"sync/atomic"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
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

const (
	ptEntries = 512
	// ptVAMask keeps the 48 translated bits of a virtual address. A table walk
	// ignores the upper 16 bits that select TTBR0 or TTBR1.
	ptVAMask = 1<<48 - 1
)

func ptIndex(va uint64, level uint) uint64 {
	return (va >> (12 + 9*(3-level))) & (ptEntries - 1)
}

func loadPTE(table []byte, idx uint64) uint64 {
	return atomic.LoadUint64((*uint64)(unsafe.Pointer(&table[idx*8])))
}

// storePTE writes one descriptor with a single 64-bit store, so a hardware
// walker on another core never reads a torn descriptor.
func storePTE(table []byte, idx uint64, desc uint64) {
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&table[idx*8])), desc)
}

// tableSet is a four-level 4KB-granule translation tree.
type tableSet struct {
	alloc   pageAllocator
	root    []byte
	rootIPA uint64
	pages   map[uint64][]byte // Every table page except the root, by IPA.
}

func newTableSet(alloc pageAllocator) (*tableSet, error) {
	root, ipa, err := alloc.allocPage()
	if err != nil {
		return nil, err
	}
	return &tableSet{alloc: alloc, root: root, rootIPA: ipa, pages: make(map[uint64][]byte, 8)}, nil
}

// leafSlot returns the level-3 table that covers va and the entry index. When
// create is false and an intermediate table is missing, it returns a nil table.
func (t *tableSet) leafSlot(va uint64, create bool) ([]byte, uint64, error) {
	va &= ptVAMask
	table := t.root
	for level := uint(0); level < 3; level++ {
		idx := ptIndex(va, level)
		desc := loadPTE(table, idx)
		next, ok := tableDescriptorIPA(desc)
		if !ok {
			if !create {
				return nil, 0, nil
			}
			page, ipa, err := t.alloc.allocPage()
			if err != nil {
				return nil, 0, err
			}
			t.pages[ipa] = page
			storePTE(table, idx, makeTableDescriptor(ipa))
			table = page
			continue
		}
		table = t.pages[next]
		if table == nil {
			return nil, 0, errors.New("hvf: page table descriptor points outside the table set")
		}
	}
	return table, ptIndex(va, 3), nil
}

// free returns every table page, including the root, to the allocator.
func (t *tableSet) free() {
	for ipa, page := range t.pages {
		t.alloc.freePage(page, ipa)
	}
	clear(t.pages)
	if t.root != nil {
		t.alloc.freePage(t.root, t.rootIPA)
		t.root = nil
	}
}

// GuestPageTable is the Stage-1 TTBR0_EL1 tree of one address space. It maps
// 4KB user pages with exact R, W and X permissions.
//
// Generation counters tell each vCPU when its cached state is stale. The TLB
// generation increments when a valid descriptor changes or disappears. The
// instruction-cache generation increments when an executable page appears or
// the host writes into one. A vCPU compares both counters with the values it
// last synchronized, and flushes through the stub only on a mismatch.
type GuestPageTable struct {
	// id is unique for the life of the process. Tables never share an id, so
	// a vCPU cannot mistake a new table for a released one at the same address.
	id uint64

	mu       sync.Mutex
	tables   *tableSet
	released bool

	tlbGen atomic.Uint64
	icGen  atomic.Uint64
	// dead is set before the tables are freed. A vCPU that sees it must not
	// run the table.
	dead atomic.Bool
}

var nextPageTableID atomic.Uint64

// NewGuestPageTable creates an empty user page table. A non-nil prefill runs on
// the new root page: x86 tables use it to link the shared kernel subtree into
// every address space. The subtree is not owned by the table, so release never
// frees it.
func NewGuestPageTable(alloc pageAllocator, prefill func(root []byte)) (*GuestPageTable, error) {
	ts, err := newTableSet(alloc)
	if err != nil {
		return nil, err
	}
	if prefill != nil {
		prefill(ts.root)
	}
	return &GuestPageTable{id: nextPageTableID.Add(1), tables: ts}, nil
}

// RootIPA returns the guest physical address of the level-0 table for
// TTBR0_EL1.
func (pt *GuestPageTable) RootIPA() uint64 {
	return pt.tables.rootIPA
}

// generations returns the TLB and instruction-cache generations.
func (pt *GuestPageTable) generations() (tlb, ic uint64) {
	return pt.tlbGen.Load(), pt.icGen.Load()
}

// MapPage inserts or replaces the 4KB leaf descriptor of va. It reports
// whether the call invalidated a cached translation: callers must then stop
// every vCPU that runs this table before they free the old backing page.
func (pt *GuestPageTable) MapPage(va, ipa uint64, at hostarch.AccessType) (invalidated bool, err error) {
	desc := userLeafDescriptor(ipa, at)
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.released {
		return false, errPageTableReleased
	}
	table, idx, err := pt.tables.leafSlot(va, true)
	if err != nil {
		return false, err
	}
	old := loadPTE(table, idx)
	storePTE(table, idx, desc)
	if old != 0 && old != desc {
		pt.tlbGen.Add(1)
		invalidated = true
	}
	if at.Execute {
		pt.icGen.Add(1)
	}
	return invalidated, nil
}

// UnmapPage clears the leaf descriptor of va. It reports whether a valid
// descriptor existed.
func (pt *GuestPageTable) UnmapPage(va uint64) (invalidated bool) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.released {
		return false
	}
	table, idx, _ := pt.tables.leafSlot(va, false)
	if table == nil || loadPTE(table, idx) == 0 {
		return false
	}
	storePTE(table, idx, 0)
	pt.tlbGen.Add(1)
	return true
}

// NoteCodeWrite records a host write into an executable page.
func (pt *GuestPageTable) NoteCodeWrite() {
	pt.icGen.Add(1)
}

// markDead forbids any further run of the table and bumps the TLB generation,
// so a vCPU that already runs it leaves the guest at its next opportunity.
func (pt *GuestPageTable) markDead() {
	pt.dead.Store(true)
	pt.tlbGen.Add(1)
}

// release frees every table page, including the root. No vCPU may run the
// table afterwards.
func (pt *GuestPageTable) release() {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.released {
		return
	}
	pt.released = true
	pt.tables.free()
}
