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
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// pageEntry is the mapping of one application page.
type pageEntry struct {
	hp    *hostPage
	perms hostarch.AccessType
}

// AddressSpace implements platform.AddressSpace with its own guest page
// tables.
//
// MapFile gives each 4KB host page a guest physical address and writes a
// leaf entry with the exact permissions. The kernel region comes from the
// shared upper half. Unmap and any change of an existing mapping invalidate
// the translations first. They release the host pages afterwards. The guest
// cannot reach a page after the Sentry reuses it.
type AddressSpace struct {
	p     *Platform
	id    uint64
	alloc *ptAllocator
	pt    *pagetables.PageTables

	// mu guards pages, the page tables and released.
	mu       sync.RWMutex
	pages    map[uint64]pageEntry
	released bool

	// gen counts invalidations. A virtual processor flushes its TLB when its
	// copy differs.
	gen atomic.Uint64

	// dead is true after Release. A Switch on a released address space fails.
	dead atomic.Bool

	// execGen counts mappings with execute permission. The arm64 stub
	// invalidates the instruction cache when it changes.
	execGen atomic.Uint64

	// activeMu guards active, the processors that run this address space.
	activeMu sync.Mutex
	active   map[*vcpu]struct{}
}

func newAddressSpace(p *Platform) (*AddressSpace, error) {
	as := &AddressSpace{
		p:      p,
		id:     p.nextASID.Add(1),
		alloc:  newPTAllocator(p.pool),
		pages:  make(map[uint64]pageEntry),
		active: make(map[*vcpu]struct{}),
	}
	if err := as.alloc.reserve(2); err != nil {
		as.alloc.drain()
		return nil, fmt.Errorf("whpx: reserve page tables: %w", err)
	}
	as.pt = pagetables.NewWithUpper(as.alloc, p.kernelPageTables(), uintptr(p.kernel.layout.base))
	return as, nil
}

// addActive records that v may execute this address space.
func (as *AddressSpace) addActive(v *vcpu) {
	as.activeMu.Lock()
	as.active[v] = struct{}{}
	as.activeMu.Unlock()
}

func (as *AddressSpace) removeActive(v *vcpu) {
	as.activeMu.Lock()
	delete(as.active, v)
	as.activeMu.Unlock()
}

// invalidate makes every processor of the address space discard its cached
// translations before it runs guest code again. Then it recycles the
// page-table pages that the last change freed. The caller holds mu.
func (as *AddressSpace) invalidate() {
	as.gen.Add(1)
	as.activeMu.Lock()
	vps := make([]*vcpu, 0, len(as.active))
	for v := range as.active {
		vps = append(vps, v)
	}
	as.activeMu.Unlock()
	for _, v := range vps {
		v.kickAndWait()
	}
	as.alloc.Recycle()
}

// releasePages drops the host page references. A failure leaves a page
// mapped in the partition while the Sentry may reuse its memory, which breaks
// isolation, so it stops the program.
func (as *AddressSpace) releasePages(hps []*hostPage) {
	for _, hp := range hps {
		if err := as.p.mem.release(hp); err != nil {
			log.Warningf("whpx: %v", err)
			panic(fmt.Sprintf("whpx: cannot unmap guest memory: %v", err))
		}
	}
}

// acquireSlices maps the 4KB pages of data into the partition.
func (as *AddressSpace) acquireSlices(data []byte, writable bool, into []*hostPage) ([]*hostPage, error) {
	if len(data)%pageSize != 0 {
		return into, fmt.Errorf("whpx: host slice of %d bytes is not a multiple of the page size", len(data))
	}
	for off := 0; off < len(data); off += pageSize {
		hp, err := as.p.mem.acquire(data[off:off+pageSize:off+pageSize], writable)
		if err != nil {
			return into, err
		}
		into = append(into, hp)
	}
	return into, nil
}

// checkRange verifies that [addr, addr+length) is a page-aligned range in the
// user part of the address space.
func (as *AddressSpace) checkRange(addr hostarch.Addr, length uint64) error {
	end := uint64(addr) + length
	if uint64(addr)&pageMask != 0 || length == 0 || length&pageMask != 0 || end < uint64(addr) || end > as.p.maxUser() {
		return platform.SegmentationFault{Addr: addr}
	}
	return nil
}

// MapFile implements platform.AddressSpace.MapFile.
func (as *AddressSpace) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, _ bool) error {
	if fr.Start&pageMask != 0 || fr.End&pageMask != 0 || !at.Any() {
		return platform.SegmentationFault{Addr: addr}
	}
	if err := as.checkRange(addr, fr.Length()); err != nil {
		return err
	}
	bs, err := f.MapInternal(fr, hostarch.AccessType{Read: true, Write: at.Write})
	if err != nil {
		return err
	}
	var hps []*hostPage
	for !bs.IsEmpty() {
		head := bs.Head()
		hps, err = as.acquireSlices(head.ToSlice(), at.Write, hps)
		if err != nil {
			as.releasePages(hps)
			return err
		}
		bs = bs.Tail()
	}
	return as.install(addr, hps, at)
}

// mapHost maps a page-aligned host slice at addr. Tests use it to map memory
// without a memmap.File.
func (as *AddressSpace) mapHost(addr hostarch.Addr, data []byte, at hostarch.AccessType) error {
	if err := as.checkRange(addr, uint64(len(data))); err != nil {
		return err
	}
	hps, err := as.acquireSlices(data, at.Write, nil)
	if err != nil {
		as.releasePages(hps)
		return err
	}
	return as.install(addr, hps, at)
}

// install writes the page-table entries for hps, which already hold host page
// references. It takes ownership of the references.
func (as *AddressSpace) install(addr hostarch.Addr, hps []*hostPage, at hostarch.AccessType) error {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		as.releasePages(hps)
		return platform.SegmentationFault{Addr: addr}
	}
	if err := as.alloc.reserve(ptReserveFor(len(hps))); err != nil {
		as.releasePages(hps)
		return fmt.Errorf("whpx: reserve page tables: %w", err)
	}
	var old []*hostPage
	opts := userPageOpts(at)
	for i, hp := range hps {
		va := uint64(addr) + uint64(i)*pageSize
		vpn := va >> pageShift
		if prev, ok := as.pages[vpn]; ok {
			old = append(old, prev.hp)
		}
		as.pages[vpn] = pageEntry{hp: hp, perms: at}
		as.pt.Map(hostarch.Addr(va), pageSize, opts, uintptr(hp.gpa))
	}
	if at.Execute {
		as.execGen.Add(1)
	}
	if len(old) > 0 || as.alloc.quarantined() > 0 {
		as.invalidate()
	}
	as.releasePages(old)
	return nil
}

// Unmap implements platform.AddressSpace.Unmap.
func (as *AddressSpace) Unmap(addr hostarch.Addr, length uint64) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return
	}
	start := uint64(addr) &^ pageMask
	end := (uint64(addr) + length + pageMask) &^ pageMask
	if end < start || end > as.p.maxUser() {
		end = as.p.maxUser()
	}
	startVPN, endVPN := start>>pageShift, end>>pageShift

	var old []*hostPage
	if endVPN-startVPN > uint64(len(as.pages)) {
		for vpn, e := range as.pages {
			if vpn >= startVPN && vpn < endVPN {
				old = append(old, e.hp)
				delete(as.pages, vpn)
			}
		}
	} else {
		for vpn := startVPN; vpn < endVPN; vpn++ {
			if e, ok := as.pages[vpn]; ok {
				old = append(old, e.hp)
				delete(as.pages, vpn)
			}
		}
	}
	as.pt.Unmap(hostarch.Addr(start), uintptr(end-start))
	if len(old) > 0 || as.alloc.quarantined() > 0 {
		as.invalidate()
	}
	as.releasePages(old)
}

// Release implements platform.AddressSpace.Release.
func (as *AddressSpace) Release() {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return
	}
	as.released = true
	as.dead.Store(true)
	old := make([]*hostPage, 0, len(as.pages))
	for vpn, e := range as.pages {
		old = append(old, e.hp)
		delete(as.pages, vpn)
	}
	as.pt.Unmap(0, uintptr(as.p.maxUser()))
	as.invalidate()
	as.releasePages(old)
	as.alloc.drain()
}

// PreFork implements platform.AddressSpace.PreFork.
func (*AddressSpace) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (*AddressSpace) PostFork() {}

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS.
func (*AddressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error {
	return nil
}

// page returns the mapping of the page that contains addr.
func (as *AddressSpace) page(addr uint64) (pageEntry, bool) {
	e, ok := as.pages[addr>>pageShift]
	return e, ok
}

// CopyOut implements platform.AddressSpaceIO.CopyOut.
func (as *AddressSpace) CopyOut(addr hostarch.Addr, src []byte) (int, error) {
	addr = hostarch.UntaggedUserAddr(addr)
	as.mu.RLock()
	defer as.mu.RUnlock()
	copied := 0
	for copied < len(src) {
		cur := uint64(addr) + uint64(copied)
		e, ok := as.page(cur)
		if !ok || !e.perms.Write {
			return copied, platform.SegmentationFault{Addr: hostarch.Addr(cur)}
		}
		copied += copy(e.hp.data[cur&pageMask:], src[copied:])
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
		e, ok := as.page(cur)
		if !ok || !(e.perms.Read || e.perms.Execute) {
			return copied, platform.SegmentationFault{Addr: hostarch.Addr(cur)}
		}
		copied += copy(dst[copied:], e.hp.data[cur&pageMask:])
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
		e, ok := as.page(cur)
		if !ok || !e.perms.Write {
			return zeroed, platform.SegmentationFault{Addr: hostarch.Addr(cur)}
		}
		chunk := min(uintptr(pageSize-cur&pageMask), toZero-zeroed)
		clear(e.hp.data[cur&pageMask : uintptr(cur&pageMask)+chunk])
		zeroed += chunk
	}
	return zeroed, nil
}

// SwapUint32 implements platform.AddressSpaceIO.SwapUint32.
func (as *AddressSpace) SwapUint32(addr hostarch.Addr, newVal uint32) (uint32, error) {
	ptr, err := as.uint32Ptr(addr, true)
	if err != nil {
		return 0, err
	}
	return atomic.SwapUint32(ptr, newVal), nil
}

// CompareAndSwapUint32 implements platform.AddressSpaceIO.CompareAndSwapUint32.
func (as *AddressSpace) CompareAndSwapUint32(addr hostarch.Addr, oldVal, newVal uint32) (uint32, error) {
	ptr, err := as.uint32Ptr(addr, true)
	if err != nil {
		return 0, err
	}
	for {
		cur := atomic.LoadUint32(ptr)
		if cur != oldVal {
			return cur, nil
		}
		if atomic.CompareAndSwapUint32(ptr, oldVal, newVal) {
			return oldVal, nil
		}
	}
}

// LoadUint32 implements platform.AddressSpaceIO.LoadUint32.
func (as *AddressSpace) LoadUint32(addr hostarch.Addr) (uint32, error) {
	ptr, err := as.uint32Ptr(addr, false)
	if err != nil {
		return 0, err
	}
	return atomic.LoadUint32(ptr), nil
}

// uint32Ptr returns a pointer to the aligned word at addr. The host mapping
// stays valid until the Sentry unmaps the page, and the Sentry serializes
// unmapping with its own use of the word.
func (as *AddressSpace) uint32Ptr(addr hostarch.Addr, write bool) (*uint32, error) {
	addr = hostarch.UntaggedUserAddr(addr)
	if uint64(addr)&3 != 0 {
		return nil, platform.SegmentationFault{Addr: addr}
	}
	as.mu.RLock()
	defer as.mu.RUnlock()
	e, ok := as.page(uint64(addr))
	if !ok || !e.perms.Read || (write && !e.perms.Write) {
		return nil, platform.SegmentationFault{Addr: addr}
	}
	return (*uint32)(unsafe.Pointer(&e.hp.data[uint64(addr)&pageMask])), nil
}
