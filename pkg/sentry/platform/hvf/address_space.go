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

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

var errNoAddressSpace = errors.New("hvf: the memory manager has no hvf address space")

// pageEntry is one mapped 4KB guest page.
type pageEntry struct {
	// data is the host view of the page. It aliases guest memory, except for
	// a private copy.
	data  []byte
	ipa   uint64
	perms hostarch.AccessType
	// copied marks data as a private slab copy of read-only host memory that
	// Hypervisor.framework refused to map. The copy never changes: the only
	// source is a read-only file descriptor of an immutable image.
	copied bool
}

// AddressSpace implements platform.AddressSpace. Stage-1 maps 4KB pages with
// exact permissions, and Stage-2 maps the 16KB host pages that contain them.
type AddressSpace struct {
	vm *vmState
	pt *GuestPageTable

	mu       sync.RWMutex
	pages    map[uint64]pageEntry // Keyed by virtual page number.
	released bool
}

func newAddressSpace(vm *vmState) (*AddressSpace, error) {
	if err := vm.retain(); err != nil {
		return nil, err
	}
	pt, err := NewGuestPageTable(vm, vm.rootPrefill())
	if err != nil {
		vm.release()
		return nil, err
	}
	return &AddressSpace{vm: vm, pt: pt, pages: make(map[uint64]pageEntry)}, nil
}

// mapPageLocked maps one 4KB host page at the virtual address va. It appends
// the entry that the new mapping replaces to stale, which the caller releases
// after stopping the vCPUs that run this address space.
func (as *AddressSpace) mapPageLocked(va uint64, page []byte, at hostarch.AccessType, stale *[]pageEntry) error {
	ipa, data, copied, err := as.vm.stagePage(page, at.Write)
	if err != nil {
		return err
	}
	entry := pageEntry{data: data, ipa: ipa, perms: at, copied: copied}
	if _, err := as.pt.MapPage(va, ipa, at); err != nil {
		as.releaseEntry(entry)
		return err
	}
	vpn := va >> pageShift
	if old, ok := as.pages[vpn]; ok {
		*stale = append(*stale, old)
	}
	as.pages[vpn] = entry
	return nil
}

// releaseEntry drops the Stage-2 reference of a page that no table maps and
// no vCPU can still translate.
func (as *AddressSpace) releaseEntry(e pageEntry) {
	if e.copied {
		as.vm.freeCopy(e.data, e.ipa)
		return
	}
	if err := as.vm.unmapHostPage(e.ipa); err != nil {
		log.Warningf("hvf: release guest page %#x: %v", e.ipa, err)
	}
}

// finishInvalidation stops every vCPU that may hold a stale translation of
// this address space, then releases the replaced pages.
func (as *AddressSpace) finishInvalidation(stale []pageEntry) {
	if len(stale) == 0 {
		return
	}
	as.vm.quiesce(as.pt)
	for _, e := range stale {
		as.releaseEntry(e)
	}
}

// MapFile implements platform.AddressSpace.MapFile. It replaces existing
// mappings in the range.
func (as *AddressSpace) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, _ bool) error {
	if uint64(addr)&pageMask4K != 0 || fr.Start&pageMask4K != 0 || fr.End&pageMask4K != 0 || fr.Length() == 0 {
		return platform.SegmentationFault{Addr: addr}
	}
	bs, err := f.MapInternal(fr, hostarch.AccessType{Read: true, Write: at.Write})
	if err != nil {
		return err
	}

	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return platform.SegmentationFault{Addr: addr}
	}
	var stale []pageEntry
	defer func() { as.finishInvalidation(stale) }()

	va := uint64(addr)
	for ; !bs.IsEmpty(); bs = bs.Tail() {
		slice := bs.Head().ToSlice()
		for off := 0; off+pageSize4K <= len(slice); off += pageSize4K {
			if err := as.mapPageLocked(va, slice[off:off+pageSize4K:off+pageSize4K], at, &stale); err != nil {
				return err
			}
			va += pageSize4K
		}
	}
	return nil
}

// Unmap implements platform.AddressSpace.Unmap. It returns after no vCPU can
// translate an address in the range.
func (as *AddressSpace) Unmap(addr hostarch.Addr, length uint64) {
	as.mu.Lock()
	defer as.mu.Unlock()
	start := uint64(addr) &^ pageMask4K
	end := (uint64(addr) + length + pageMask4K) &^ pageMask4K
	startVPN, endVPN := start>>pageShift, end>>pageShift
	var stale []pageEntry
	remove := func(vpn uint64) {
		entry, ok := as.pages[vpn]
		if !ok {
			return
		}
		delete(as.pages, vpn)
		as.pt.UnmapPage(vpn << pageShift)
		stale = append(stale, entry)
	}
	if endVPN < startVPN || endVPN-startVPN > uint64(len(as.pages)) {
		for vpn := range as.pages {
			if vpn >= startVPN && (endVPN < startVPN || vpn < endVPN) {
				remove(vpn)
			}
		}
	} else {
		for vpn := startVPN; vpn < endVPN; vpn++ {
			remove(vpn)
		}
	}
	as.finishInvalidation(stale)
}

// Release implements platform.AddressSpace.Release. It frees the page tables
// and drops every Stage-2 reference.
func (as *AddressSpace) Release() {
	as.mu.Lock()
	if as.released {
		as.mu.Unlock()
		return
	}
	as.released = true
	entries := make([]pageEntry, 0, len(as.pages))
	for _, e := range as.pages {
		entries = append(entries, e)
	}
	clear(as.pages)
	as.mu.Unlock()

	as.vm.retire(as.pt)
	for _, e := range entries {
		as.releaseEntry(e)
	}
	as.vm.release()
}

// PreFork implements platform.AddressSpace.PreFork.
func (*AddressSpace) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (*AddressSpace) PostFork() {}

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS.
func (*AddressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error {
	return nil
}

// pageFor returns the entry of the page that contains addr, or a
// SegmentationFault when the page is missing or lacks the access.
func (as *AddressSpace) pageFor(addr uint64, need func(hostarch.AccessType) bool) (pageEntry, error) {
	entry, ok := as.pages[addr>>pageShift]
	if !ok || !need(entry.perms) {
		return pageEntry{}, platform.SegmentationFault{Addr: hostarch.Addr(addr)}
	}
	return entry, nil
}

func canRead(at hostarch.AccessType) bool  { return at.Read || at.Execute }
func canWrite(at hostarch.AccessType) bool { return at.Write }

// noteWrite records a host write so a vCPU that runs this address space
// invalidates its instruction cache before it executes the new bytes.
func (as *AddressSpace) noteWrite(e pageEntry) {
	if e.perms.Execute {
		as.pt.NoteCodeWrite()
	}
}

// CopyOut implements platform.AddressSpaceIO.CopyOut.
func (as *AddressSpace) CopyOut(addr hostarch.Addr, src []byte) (int, error) {
	addr = hostarch.UntaggedUserAddr(addr)
	as.mu.RLock()
	defer as.mu.RUnlock()
	copied := 0
	for copied < len(src) {
		cur := uint64(addr) + uint64(copied)
		entry, err := as.pageFor(cur, canWrite)
		if err != nil {
			return copied, err
		}
		copied += copy(entry.data[cur&pageMask4K:], src[copied:])
		as.noteWrite(entry)
	}
	return copied, nil
}

// CopyIn implements platform.AddressSpaceIO.CopyIn.
func (as *AddressSpace) CopyIn(addr hostarch.Addr, dst []byte) (int, error) {
	addr = hostarch.UntaggedUserAddr(addr)
	as.mu.RLock()
	defer as.mu.RUnlock()
	copied := 0
	for copied < len(dst) {
		cur := uint64(addr) + uint64(copied)
		entry, err := as.pageFor(cur, canRead)
		if err != nil {
			return copied, err
		}
		copied += copy(dst[copied:], entry.data[cur&pageMask4K:])
	}
	return copied, nil
}

// ZeroOut implements platform.AddressSpaceIO.ZeroOut.
func (as *AddressSpace) ZeroOut(addr hostarch.Addr, toZero uintptr) (uintptr, error) {
	addr = hostarch.UntaggedUserAddr(addr)
	as.mu.RLock()
	defer as.mu.RUnlock()
	zeroed := uintptr(0)
	for zeroed < toZero {
		cur := uint64(addr) + uint64(zeroed)
		entry, err := as.pageFor(cur, canWrite)
		if err != nil {
			return zeroed, err
		}
		chunk := min(len(entry.data)-int(cur&pageMask4K), int(toZero-zeroed))
		clear(entry.data[cur&pageMask4K:][:chunk])
		as.noteWrite(entry)
		zeroed += uintptr(chunk)
	}
	return zeroed, nil
}

// uint32Ptr returns a pointer to the 32-bit word at addr. The caller must
// hold as.mu for reading while it uses the pointer.
func (as *AddressSpace) uint32Ptr(addr hostarch.Addr, need func(hostarch.AccessType) bool) (*uint32, pageEntry, error) {
	addr = hostarch.UntaggedUserAddr(addr)
	if uint64(addr)&3 != 0 {
		return nil, pageEntry{}, platform.SegmentationFault{Addr: addr}
	}
	entry, err := as.pageFor(uint64(addr), need)
	if err != nil {
		return nil, pageEntry{}, err
	}
	return (*uint32)(unsafe.Pointer(&entry.data[uint64(addr)&pageMask4K])), entry, nil
}

// SwapUint32 implements platform.AddressSpaceIO.SwapUint32.
func (as *AddressSpace) SwapUint32(addr hostarch.Addr, newVal uint32) (uint32, error) {
	as.mu.RLock()
	defer as.mu.RUnlock()
	ptr, entry, err := as.uint32Ptr(addr, func(at hostarch.AccessType) bool { return at.Read && at.Write })
	if err != nil {
		return 0, err
	}
	old := atomic.SwapUint32(ptr, newVal)
	as.noteWrite(entry)
	return old, nil
}

// CompareAndSwapUint32 implements platform.AddressSpaceIO.CompareAndSwapUint32.
func (as *AddressSpace) CompareAndSwapUint32(addr hostarch.Addr, oldVal, newVal uint32) (uint32, error) {
	as.mu.RLock()
	defer as.mu.RUnlock()
	ptr, entry, err := as.uint32Ptr(addr, func(at hostarch.AccessType) bool { return at.Read && at.Write })
	if err != nil {
		return 0, err
	}
	for {
		cur := atomic.LoadUint32(ptr)
		if cur != oldVal {
			return cur, nil
		}
		if atomic.CompareAndSwapUint32(ptr, oldVal, newVal) {
			as.noteWrite(entry)
			return oldVal, nil
		}
	}
}

// LoadUint32 implements platform.AddressSpaceIO.LoadUint32.
func (as *AddressSpace) LoadUint32(addr hostarch.Addr) (uint32, error) {
	as.mu.RLock()
	defer as.mu.RUnlock()
	ptr, _, err := as.uint32Ptr(addr, func(at hostarch.AccessType) bool { return at.Read })
	if err != nil {
		return 0, err
	}
	return atomic.LoadUint32(ptr), nil
}
