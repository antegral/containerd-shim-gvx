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

//go:build darwin

package hvf

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	hostPageMask     = hostPageSize - 1
	slabPagesPerHost = hostPageSize / pageSize4K

	// Guest physical layout. Slab blocks hold page tables, the vector page and
	// CommPages. Host blocks alias Sentry memory. Both ranges must fit in the
	// IPA size of the VM, which is 36 bits by default on Apple silicon.
	slabBaseIPA uint64 = 0x1_0000_0000
	hostBaseIPA uint64 = 0x2_0000_0000
)

var (
	errPlatformClosed = errors.New("hvf: platform closed")
	// errHostBlockRejected reports that Hypervisor.framework refused a host
	// memory region. It wraps the framework error.
	errHostBlockRejected = errors.New("hvf: hv_vm_map rejected the host memory")
)

type slabPage struct {
	page []byte
	ipa  uint64
}

// slabBlock is one 16KB anonymous host mapping that Stage-2 maps at ipa.
type slabBlock struct {
	mem []byte
	ipa uint64
}

// hostBlock is one 16KB host page mapped into Stage-2.
type hostBlock struct {
	ipa  uint64
	refs int // Guest 4KB pages that reference the block.
}

// vmState owns one Hypervisor.framework VM from hv_vm_create to hv_vm_destroy.
type vmState struct {
	maxIPA uint64 // Exclusive upper bound of the guest physical address space.

	mu     sync.Mutex
	closed bool

	// Slab allocator for 4KB table pages.
	slabs       []slabBlock
	slabCur     []byte
	slabCurIPA  uint64
	slabUsed    int
	nextSlabIPA uint64
	freePages   []slabPage
	pagesInUse  int

	// Host blocks keyed by the 16KB-aligned host address.
	blocks     map[uintptr]*hostBlock
	blockByIPA map[uint64]uintptr
	nextHost   uint64
	freeHost   []uint64

	kernel kernelMap // Process-wide TTBR1 tables and vector page.
	pool   workerPool

	// users counts address spaces that still use slab memory. The slab memory
	// stays mapped until the last user releases it, even after Close.
	users     int
	destroyed bool
}

var vmGlobal struct {
	sync.Mutex
	vm       *vmState
	refs     int
	deathErr error // Set when a previous hv_vm_destroy failed.
}

// acquireVM returns the shared VM, creating it on first use.
func acquireVM() (*vmState, error) {
	vmGlobal.Lock()
	defer vmGlobal.Unlock()
	if vmGlobal.deathErr != nil {
		return nil, fmt.Errorf("hvf: previous VM could not be destroyed: %w", vmGlobal.deathErr)
	}
	if vmGlobal.vm == nil {
		if err := createVMWithEntitlement(); err != nil {
			return nil, err
		}
		v, err := newVMState()
		if err != nil {
			return nil, errors.Join(err, hvVMDestroy())
		}
		vmGlobal.vm = v
	}
	vmGlobal.refs++
	return vmGlobal.vm, nil
}

// releaseVM drops one Platform reference and destroys the VM with the last.
func releaseVM(v *vmState) error {
	vmGlobal.Lock()
	defer vmGlobal.Unlock()
	vmGlobal.refs--
	if vmGlobal.refs > 0 {
		return nil
	}
	vmGlobal.vm = nil
	if err := v.shutdown(); err != nil {
		vmGlobal.deathErr = err
		return err
	}
	return nil
}

func newVMState() (*vmState, error) {
	bits, err := hvDefaultIPABits()
	if err != nil {
		return nil, err
	}
	v := &vmState{
		maxIPA:      1 << bits,
		nextSlabIPA: slabBaseIPA,
		nextHost:    hostBaseIPA,
		blocks:      make(map[uintptr]*hostBlock),
		blockByIPA:  make(map[uint64]uintptr),
	}
	if hostBaseIPA >= v.maxIPA {
		return nil, fmt.Errorf("hvf: guest physical address space of %d bits is too small", bits)
	}
	maxVCPUs, err := hvVMMaxVCPUs()
	if err != nil {
		return nil, err
	}
	slots := min(maxVCPUs, kernelCommPages)
	if slots < 1 {
		return nil, fmt.Errorf("hvf: the VM allows %d vCPUs", maxVCPUs)
	}
	if err := v.initKernel(slots); err != nil {
		v.releaseSlabs()
		return nil, err
	}
	v.pool.init(v, slots)
	return v, nil
}

// shutdown stops every vCPU thread and destroys the VM. hv_vm_destroy removes
// every Stage-2 mapping, so no per-block unmap is needed. Address spaces that
// outlive the Platform keep their slab memory until they release it.
func (v *vmState) shutdown() error {
	v.mu.Lock()
	v.closed = true
	v.mu.Unlock()

	err := v.pool.stop()

	v.mu.Lock()
	clear(v.blocks)
	clear(v.blockByIPA)
	v.freeHost = nil
	v.mu.Unlock()
	if err != nil {
		return err
	}
	if err := hvVMDestroy(); err != nil {
		return err
	}
	v.mu.Lock()
	v.destroyed = true
	if v.users == 0 {
		v.releaseSlabsLocked()
	}
	v.mu.Unlock()
	return nil
}

// rootPrefill returns the hook that links shared kernel mappings into a new
// user root, or nil.
func (v *vmState) rootPrefill() func(root []byte) {
	return v.kernel.prefillRoot
}

// retain registers an address space that uses slab memory.
func (v *vmState) retain() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return errPlatformClosed
	}
	v.users++
	return nil
}

// release unregisters an address space and frees the slab memory when the VM
// is already destroyed and no user remains.
func (v *vmState) release() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.users--
	if v.users == 0 && v.destroyed {
		v.releaseSlabsLocked()
	}
}

func (v *vmState) releaseSlabs() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.releaseSlabsLocked()
}

func (v *vmState) releaseSlabsLocked() {
	for _, s := range v.slabs {
		if err := unix.Munmap(s.mem); err != nil {
			panic(fmt.Sprintf("hvf: munmap slab: %v", err))
		}
	}
	v.slabs = nil
	v.slabCur = nil
	v.freePages = nil
}

// allocPage implements pageAllocator.
func (v *vmState) allocPage() ([]byte, uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, 0, errPlatformClosed
	}
	if n := len(v.freePages); n > 0 {
		p := v.freePages[n-1]
		v.freePages = v.freePages[:n-1]
		clear(p.page)
		v.pagesInUse++
		return p.page, p.ipa, nil
	}
	if v.slabCur == nil || v.slabUsed == slabPagesPerHost {
		if err := v.newSlabLocked(); err != nil {
			return nil, 0, err
		}
	}
	off := v.slabUsed * pageSize4K
	v.slabUsed++
	v.pagesInUse++
	return v.slabCur[off : off+pageSize4K : off+pageSize4K], v.slabCurIPA + uint64(off), nil
}

// newSlabLocked maps one more 16KB slab block into Stage-2.
func (v *vmState) newSlabLocked() error {
	if v.nextSlabIPA+hostPageSize > hostBaseIPA {
		return errors.New("hvf: slab guest physical range exhausted")
	}
	mem, err := unix.Mmap(-1, 0, hostPageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return fmt.Errorf("hvf: allocate slab block: %w", err)
	}
	ipa := v.nextSlabIPA
	if err := hvVMMap(uintptr(unsafe.Pointer(unsafe.SliceData(mem))), ipa, hostPageSize, hvMemoryRead|hvMemoryWrite|hvMemoryExec); err != nil {
		return errors.Join(err, unix.Munmap(mem))
	}
	v.nextSlabIPA += hostPageSize
	v.slabs = append(v.slabs, slabBlock{mem: mem, ipa: ipa})
	v.slabCur = mem
	v.slabCurIPA = ipa
	v.slabUsed = 0
	return nil
}

// freePage implements pageAllocator.
func (v *vmState) freePage(page []byte, ipa uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pagesInUse--
	if v.destroyed {
		return
	}
	v.freePages = append(v.freePages, slabPage{page: page, ipa: ipa})
}

// slabStats reports slab usage for leak tests.
type slabStats struct {
	blocks     int // 16KB slab blocks ever mapped.
	pagesInUse int // 4KB pages handed out and not freed.
}

func (v *vmState) slabStats() slabStats {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slabStats{blocks: len(v.slabs), pagesInUse: v.pagesInUse}
}

// mapHostPage maps the 16KB host page that contains the 4KB page into Stage-2
// and returns the guest physical address of the 4KB page. Each call must pair
// with one unmapHostPage. Blocks stay mapped while any guest page references
// them, so a reused host address can never alias a stale guest physical page.
func (v *vmState) mapHostPage(page []byte) (uint64, error) {
	base := uintptr(unsafe.Pointer(unsafe.SliceData(page)))
	if len(page) != pageSize4K || base&pageMask4K != 0 {
		return 0, fmt.Errorf("hvf: host page %#x is not a 4KB aligned page", base)
	}
	block := base &^ hostPageMask
	sub := uint64(base & hostPageMask)

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return 0, errPlatformClosed
	}
	if b, ok := v.blocks[block]; ok {
		b.refs++
		return b.ipa + sub, nil
	}
	ipa, err := v.allocHostIPALocked()
	if err != nil {
		return 0, err
	}
	if err := hvVMMap(block, ipa, hostPageSize, hvMemoryRead|hvMemoryWrite|hvMemoryExec); err != nil {
		v.freeHost = append(v.freeHost, ipa)
		return 0, fmt.Errorf("%w: %w", errHostBlockRejected, err)
	}
	v.blocks[block] = &hostBlock{ipa: ipa, refs: 1}
	v.blockByIPA[ipa] = block
	return ipa + sub, nil
}

// stagePage prepares one 4KB host page for a guest mapping. It returns the
// guest physical address and the host view that the address space reads and
// writes.
//
// Hypervisor.framework rejects every memory region whose backing file was
// opened read-only: hv_vm_map returns HV_ERROR for RWX, RX and R requests alike
// (probe on macOS 26: anonymous, shared and private mappings of a read-write
// descriptor map, a MAP_SHARED PROT_READ mapping of an O_RDONLY descriptor does
// not). In practice the EROFS layer images take this path: the Sentry maps each
// image through a read-only descriptor, and every guest file page (ELF text,
// libraries, read-only data) arrives here. The busybox, python and node image
// tests copy about 5900 pages this way. For a read-only request only, stagePage
// then copies the page into a slab page. The image is immutable, so the copy
// stays equal to the file. A writable request never takes this path, because a
// copy of writable shared memory would diverge from the original. Pages from
// pgalloc memory files, which the Sentry maps read-write, always map directly.
func (v *vmState) stagePage(page []byte, write bool) (ipa uint64, data []byte, copied bool, err error) {
	ipa, err = v.mapHostPage(page)
	if err == nil {
		return ipa, page, false, nil
	}
	if code, ok := hvCode(err); write || !ok || code != hvErrGeneral {
		return 0, nil, false, err
	}
	slab, slabIPA, aerr := v.allocPage()
	if aerr != nil {
		return 0, nil, false, errors.Join(err, aerr)
	}
	copy(slab, page)
	return slabIPA, slab, true, nil
}

// freeCopy returns the slab page of a private copy.
func (v *vmState) freeCopy(data []byte, ipa uint64) {
	v.freePage(data, ipa)
}

// unmapHostPage drops one reference taken by mapHostPage and unmaps the block
// with the last reference.
func (v *vmState) unmapHostPage(ipa uint64) error {
	blockIPA := ipa &^ hostPageMask
	v.mu.Lock()
	defer v.mu.Unlock()
	host, ok := v.blockByIPA[blockIPA]
	if !ok {
		if v.closed {
			return nil // shutdown already removed every block.
		}
		return fmt.Errorf("hvf: guest physical page %#x has no host block", ipa)
	}
	b := v.blocks[host]
	b.refs--
	if b.refs > 0 {
		return nil
	}
	delete(v.blocks, host)
	delete(v.blockByIPA, blockIPA)
	if err := hvVMUnmap(blockIPA, hostPageSize); err != nil {
		return err // The address stays reserved: its mapping state is unknown.
	}
	v.freeHost = append(v.freeHost, blockIPA)
	return nil
}

func (v *vmState) allocHostIPALocked() (uint64, error) {
	if n := len(v.freeHost); n > 0 {
		ipa := v.freeHost[n-1]
		v.freeHost = v.freeHost[:n-1]
		return ipa, nil
	}
	if v.nextHost+hostPageSize > v.maxIPA {
		return 0, errors.New("hvf: guest physical address space exhausted")
	}
	ipa := v.nextHost
	v.nextHost += hostPageSize
	return ipa, nil
}

// hostBlockCount returns the number of mapped host blocks for tests.
func (v *vmState) hostBlockCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.blocks)
}
