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

//go:build darwin && arm64

package systrap

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// pageChunkSize is the amount of address space that the pool maps at once.
const pageChunkSize = 8 << 20

// pagePool hands out host pages that only the Sentry owns. The Sentry writes
// them through its own mapping and shares them with exactly one stub task, by
// remapping, as thread blocks, patched code copies and trampoline islands.
//
// The pool never returns memory to the kernel. A freed page is zeroed on its
// next allocation, so a page never leaks guest-visible bytes between tasks.
type pagePool struct {
	mu     sync.Mutex
	chunks []uint64
	next   uint64
	end    uint64
	free   map[int][]uint64
	self   machPort
}

func newPagePool() *pagePool {
	return &pagePool{self: selfTask(), free: make(map[int][]uint64)}
}

// alloc returns the Sentry address of one zeroed host page.
func (p *pagePool) alloc() (uint64, error) { return p.allocSpan(1) }

// allocSpan returns the Sentry address of pages contiguous zeroed host pages.
func (p *pagePool) allocSpan(pages int) (uint64, error) {
	size := uint64(pages) * blockSize
	p.mu.Lock()
	defer p.mu.Unlock()
	var addr uint64
	if list := p.free[pages]; len(list) > 0 {
		addr = list[len(list)-1]
		p.free[pages] = list[:len(list)-1]
		clear(unsafe.Slice((*byte)(addrPtr(addr)), size))
		return addr, nil
	}
	if p.end-p.next < size {
		base, err := vmAllocate(p.self, pageChunkSize)
		if err != nil {
			return 0, fmt.Errorf("allocate %d bytes for the page pool: %w", pageChunkSize, err)
		}
		p.chunks = append(p.chunks, base)
		p.next, p.end = base, base+pageChunkSize
	}
	addr = p.next
	p.next += size
	return addr, nil
}

// release returns a page to the pool. The caller must have unmapped it from
// every stub task first.
func (p *pagePool) release(addr uint64) { p.releaseSpan(addr, 1) }

// releaseSpan returns a span from allocSpan to the pool.
func (p *pagePool) releaseSpan(addr uint64, pages int) {
	p.mu.Lock()
	p.free[pages] = append(p.free[pages], addr)
	p.mu.Unlock()
}

// close unmaps the whole pool.
func (p *pagePool) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var errs []error
	for _, c := range p.chunks {
		if err := vmDeallocate(p.self, c, pageChunkSize); err != nil {
			errs = append(errs, err)
		}
	}
	p.chunks, p.free, p.next, p.end = nil, make(map[int][]uint64), 0, 0
	return errors.Join(errs...)
}

// pageBytes views one pool page as a byte slice.
func pageBytes(addr uint64) []byte {
	return unsafe.Slice((*byte)(addrPtr(addr)), blockSize)
}

// flushCode makes stores to code visible to instruction fetch on every core.
// The stub fetches the bytes through a different virtual alias of the same
// physical pages, so the Sentry flushes through its own alias.
func flushCode(code []byte) {
	if len(code) == 0 {
		return
	}
	icacheInvalidate(unsafe.Pointer(&code[0]), uintptr(len(code)))
}
