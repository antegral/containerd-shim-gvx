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

//go:build windows

package systrap

import (
	"errors"
	"fmt"
	"math/rand/v2"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// A trampoline island is one page of slots in the guest address space. A
// patched system call instruction jumps to a slot, so the slot must lie within
// the reach of the jump. The island is a sealed mapping that the memory manager
// knows, so that the guest cannot map over it. The engine maps a private page
// of slot code over the frame that the memory manager holds.

// winIslandReach is the largest distance between a patched instruction and the
// island that holds its slot. A B instruction reaches 128MiB on arm64. The
// margin covers the page size and the slot branch back.
const winIslandReach = 120 << 20

// island is one page of trampoline slots.
type island struct {
	base uint64
	page privPage
	// used is the number of bytes of the page that slots occupy.
	used uint32
	// slots maps the offset of each slot to the address of its patched site.
	slots map[uint32]uint64
}

// islandRange tells MapFile what to do with a mapping that touches an island.
// The memory manager populates the sealed mapping of an island when it maps the
// island, and the island keeps its own page. skip is true for such a mapping.
// A mapping that covers an island partly is an error.
func (as *addressSpace) islandRange(va, n uint64) (skip bool, err error) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.reserved) == 0 && len(as.islands) == 0 {
		return false, nil
	}
	if _, pending := as.reserved[va]; pending && n == blockSize {
		return true, nil
	}
	for base := range as.islands {
		if base < va+n && va < base+blockSize {
			if va == base && n == blockSize {
				return true, nil
			}
			return false, fmt.Errorf("mapping [%#x, %#x) overlaps the trampoline island at %#x", va, va+n, base)
		}
	}
	return false, nil
}

// dropIslandsLocked forgets the islands in [start, end) and frees their pages.
// Callers hold mu.
func (as *addressSpace) dropIslandsLocked(start, end uint64) {
	for base, isl := range as.islands {
		if base < end && start < base+blockSize {
			delete(as.islands, base)
			as.p.priv.release(isl.page)
		}
	}
}

// releaseIslandsLocked frees every island. Callers hold mu.
func (as *addressSpace) releaseIslandsLocked() {
	for base, isl := range as.islands {
		as.p.priv.release(isl.page)
		delete(as.islands, base)
	}
}

// inIsland reports whether pc lies in an island.
func (as *addressSpace) inIsland(pc uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	_, ok := as.islands[blockRound(pc)]
	return ok
}

// slotStartSite returns the site of the slot that starts at pc, if pc is the
// first address of a slot.
func (as *addressSpace) slotStartSite(pc uint64) (uint64, bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	isl := as.islands[blockRound(pc)]
	if isl == nil {
		return 0, false
	}
	site, ok := isl.slots[uint32(pc-isl.base)]
	return site, ok
}

// slotAtTail returns the site of the slot whose tail is at tail.
func (as *addressSpace) slotAtTail(tail uint64) (uint64, bool) {
	return as.slotStartSite(tail - winSlotTailOffset)
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// guestPageOK reports whether the page at va lies in a guest window.
func (as *addressSpace) guestPageOK(va uint64) bool {
	p := as.p
	if va < p.userMin || va+blockSize > p.userMax {
		return false
	}
	inLow := p.lowWindow && va >= lowBase && va+blockSize <= lowLimit
	inHigh := va >= winBase
	return inLow || inHigh
}

// installSlot allocates a slot within reach of site, lets encode write the slot
// code, and returns the address of the slot. The page of the slot is the
// private page that the stub maps for execution, so the slot is live as soon as
// the call returns and the instruction cache of the stub is flushed.
func (as *addressSpace) installSlot(ctx context.Context, mm platform.MemoryManager, site uint64, encode func(buf []byte, slotVA uint64) error) (uint64, error) {
	isl, off, err := as.allocSlot(ctx, mm, site)
	if err != nil {
		return 0, err
	}
	slotVA := isl.base + uint64(off)
	if err := encode(isl.page.bytes()[off:off+winSlotSize], slotVA); err != nil {
		return 0, err
	}
	as.mu.Lock()
	isl.slots[off] = site
	as.mu.Unlock()
	if err := flushInstructionCache(as.sp.proc, uintptr(slotVA), winSlotSize); err != nil {
		return 0, err
	}
	return slotVA, nil
}

// allocSlot returns space for a slot within reach of site. It creates an island
// through the memory manager when no island has room.
func (as *addressSpace) allocSlot(ctx context.Context, mm platform.MemoryManager, site uint64) (*island, uint32, error) {
	for range 3 {
		as.mu.Lock()
		for _, isl := range as.islands {
			if absDiff(isl.base, site) < winIslandReach && isl.used+winSlotSize <= blockSize {
				off := isl.used
				isl.used += winSlotSize
				as.mu.Unlock()
				return isl, off, nil
			}
		}
		as.mu.Unlock()
		if err := as.newIsland(ctx, mm, site); err != nil {
			return nil, 0, err
		}
	}
	return nil, 0, errors.New("no trampoline island has room")
}

// newIsland reserves a sealed mapping within reach of near through the memory
// manager and maps a private page of slots there.
func (as *addressSpace) newIsland(ctx context.Context, mm platform.MemoryManager, near uint64) error {
	var lastErr error
	for range 128 {
		off := (uint64(rand.Int64N(winIslandReach-(4<<20))) + 2<<20) &^ (blockSize - 1)
		var cand uint64
		if rand.IntN(2) == 0 {
			if near < off {
				continue
			}
			cand = near - off
		} else {
			cand = near + off
		}
		cand = blockRound(cand)
		if !as.guestPageOK(cand) {
			continue
		}
		as.mu.Lock()
		if _, busy := as.reserved[cand]; busy || as.islands[cand] != nil || as.released {
			as.mu.Unlock()
			continue
		}
		as.reserved[cand] = struct{}{}
		as.mu.Unlock()

		_, err := mm.MMap(ctx, memmap.MMapOpts{
			Length:    blockSize,
			Addr:      hostarch.Addr(cand),
			Fixed:     true,
			NoReplace: true,
			Private:   true,
			Name:      "[systrap]",
			Sealed:    true,
			Perms:     hostarch.AccessType{Read: true, Execute: true},
			MaxPerms:  hostarch.AccessType{Read: true, Execute: true},
		})
		if err != nil {
			as.mu.Lock()
			delete(as.reserved, cand)
			as.mu.Unlock()
			lastErr = err
			continue
		}
		return as.installIsland(cand)
	}
	if lastErr == nil {
		lastErr = unix.ENOMEM
	}
	return fmt.Errorf("find an address within 120MiB for a trampoline island: %w", lastErr)
}

// installIsland maps a zeroed private page as read and execute at base.
func (as *addressSpace) installIsland(base uint64) error {
	pg, err := as.p.priv.alloc()
	if err != nil {
		as.dropReservation(base)
		return err
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	delete(as.reserved, base)
	if as.released {
		as.p.priv.release(pg)
		return errAddressSpaceReleased
	}
	if err := as.win.Map(base, blockSize, &pg.chunk.ref, pg.off, viewReadExec); err != nil {
		as.p.priv.release(pg)
		return as.mapErr(err)
	}
	as.islands[base] = &island{base: base, page: pg, slots: make(map[uint32]uint64)}
	return flushInstructionCache(as.sp.proc, uintptr(base), blockSize)
}

func (as *addressSpace) dropReservation(base uint64) {
	as.mu.Lock()
	delete(as.reserved, base)
	as.mu.Unlock()
}
