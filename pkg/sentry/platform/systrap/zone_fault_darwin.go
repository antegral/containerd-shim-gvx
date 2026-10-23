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
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/usermem"
)

// zoneFault handles the faults that the zone mode causes. It returns false for
// every fault that has another cause.
//
// A guest pointer into the zone has no mapping at its own address, because
// the stub holds the zone at the bias. Three faults follow from that:
//
//   - A jump to a guest address of the zone fetches from an unmapped address.
//     The Sentry continues the thread at the biased address.
//   - A load or store through such a pointer faults. The Sentry replaces the
//     instruction by a slot that biases the base register. The instruction can
//     also be the guest instruction of an x18 slot. The Sentry then replaces
//     that word of the slot.
//   - A fault inside such a slot belongs to the guest instruction at the
//     site. The Sentry takes the bias out of the register and reports the
//     fault at the site.
func (c *Context) zoneFault(ctx context.Context, mm platform.MemoryManager, as *addressSpace, th *thread, ac *arch.Context64, sig uint64, ec, esr uint32, far, pc uint64) (signalAction, bool) {
	if (sig != darwinSIGSEGV && sig != darwinSIGBUS) || (ec != ecInstructionAbort && ec != ecDataAbort) {
		return signalAction{}, false
	}
	sm := th.sm
	if as.inIsland(pc) {
		meta, start, ok := as.slotWithin(pc)
		if !ok || meta.kind != siteMem || ec != ecDataAbort {
			return signalAction{}, false
		}
		if (pc-start)/4 == uint64(meta.body) {
			// The biased copy of the instruction faulted, so the slot has added
			// the bias to the base register and has not removed it yet.
			bias := uint64(zoneBias)
			addToRegister(&sm.MC.SS, meta.reg, -bias)
			if far >= zoneBias && far < zoneBias+zoneLimit {
				far -= zoneBias
			}
			if meta.scratch&memFixesValue != 0 {
				if err := restoreSpilledScratch(ctx, mm, &sm.MC.SS); err != nil {
					return contextErr(err, unix.EFAULT), true
				}
			}
		}
		site := meta.site
		if as.inIsland(site) {
			// The slot replaces the guest instruction of an x18 slot. The fault
			// belongs to the guest instruction at the site of the x18 slot, with
			// the borrowed scratch register restored.
			outer, _, found := as.slotWithin(site)
			if !found || outer.kind != siteX18 {
				return signalAction{}, false
			}
			sm.MC.SS.X[outer.scratch] = sm.Spill
			site = outer.site
		}
		sm.MC.SS.PC = site
		if esr&esrWnR != 0 {
			// A store into a block that the guest maps writable and executable
			// is not a fault of the guest.
			if act, done := c.storeToExecBlock(as, sm, site, far); done {
				return act, true
			}
		}
		return c.reportFault(th, ac, sig, ec, esr, far, site), true
	}
	switch {
	case ec == ecInstructionAbort && inZoneGuest(pc) && as.zoneMappedExec(pc):
		sm.MC.SS.PC = pc + zoneBias
		return signalAction{resume: true}, true
	case ec == ecDataAbort && inZoneGuest(far) && as.zoneMappedAt(far):
		ok, err := as.patchMemSite(ctx, mm, pc)
		if err != nil {
			return contextErr(fmt.Errorf("patch the access at %#x: %w", pc, err), unix.ENOMEM), true
		}
		if ok {
			return signalAction{resume: true}, true
		}
	}
	return signalAction{}, false
}

// zoneBodyFault handles a fault of a guest instruction that runs inside an x18
// slot. It must run before recoverX18Slot, which rewinds the thread to the
// site of the slot. It returns false for every other fault.
func (c *Context) zoneBodyFault(ctx context.Context, mm platform.MemoryManager, as *addressSpace, sig uint64, ec uint32, far, pc uint64) (signalAction, bool) {
	if (sig != darwinSIGSEGV && sig != darwinSIGBUS) || ec != ecDataAbort || !inZoneGuest(far) || !as.zoneMappedAt(far) {
		return signalAction{}, false
	}
	meta, start, ok := as.slotWithin(pc)
	if !ok || meta.kind != siteX18 {
		return signalAction{}, false
	}
	if _, body, ok := x18Restart(meta.kind, int(meta.body), uint32(pc-start)); !ok || !body {
		return signalAction{}, false
	}
	patched, err := as.patchSlotWord(ctx, mm, pc)
	if err != nil {
		return contextErr(fmt.Errorf("patch the access in the slot at %#x: %w", pc, err), unix.ENOMEM), true
	}
	if !patched {
		return signalAction{}, false
	}
	return signalAction{resume: true}, true
}

// addToRegister adds delta to a general-purpose register of the thread state.
func addToRegister(ss *armThreadState, reg uint8, delta uint64) {
	switch {
	case reg < 29:
		ss.X[reg] += delta
	case reg == 29:
		ss.FP += delta
	case reg == 30:
		ss.LR += delta
	}
}

// slotSpillBelowSP is the distance below the guest stack pointer at which a
// memory slot spills x16 and x17 before it borrows them.
const slotSpillBelowSP = 512

// restoreSpilledScratch puts the guest values of x16 and x17 back into the
// thread state. A memory slot that stores its base register spills the two
// registers below the guest stack pointer, borrows them, and reloads them after
// the instruction. A fault inside the instruction leaves the borrowed values in
// the registers.
func restoreSpilledScratch(ctx context.Context, mm platform.MemoryManager, ss *armThreadState) error {
	var saved [16]byte
	if _, err := mm.CopyIn(ctx, hostarch.Addr(ss.SP-slotSpillBelowSP), saved[:], usermem.IOOpts{IgnorePermissions: true}); err != nil {
		return fmt.Errorf("read the registers that a slot spilled below sp %#x: %w", ss.SP, err)
	}
	ss.X[16] = binary.LittleEndian.Uint64(saved[0:])
	ss.X[17] = binary.LittleEndian.Uint64(saved[8:])
	return nil
}

// zoneMappedAt reports whether the guest maps the block that holds the zone
// address a.
func (as *addressSpace) zoneMappedAt(a uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	_, ok := as.zoneMapped[blockRound(a+zoneBias)]
	return ok
}

// zoneMappedExec reports whether the guest maps the zone address a as code.
func (as *addressSpace) zoneMappedExec(a uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	_, ok := as.blocks[blockRound(a+zoneBias)]
	return ok
}

// patchMemSite replaces the load or store at the stub address pc by a branch
// to a memory slot. It reports false when the instruction has a form that no
// slot covers. It also reports true when another thread patched the site
// first, so the caller resumes the thread in both cases.
func (as *addressSpace) patchMemSite(ctx context.Context, mm platform.MemoryManager, pc uint64) (bool, error) {
	base := blockRound(pc)
	as.mu.Lock()
	blk := as.blocks[base]
	if as.released || blk == nil || blk.state != blockExec || blk.priv == 0 {
		as.mu.Unlock()
		return false, nil
	}
	priv := blk.priv
	as.mu.Unlock()
	valid := func() bool {
		return !as.released && as.blocks[base] == blk && blk.state == blockExec && blk.priv == priv
	}
	return as.installMemSlot(ctx, mm, pc, pageBytes(priv), pc-base, valid)
}

// patchSlotWord replaces the guest instruction that sits in a slot of an
// island, at the stub address pc, by a branch to a memory slot.
func (as *addressSpace) patchSlotWord(ctx context.Context, mm platform.MemoryManager, pc uint64) (bool, error) {
	base := blockRound(pc)
	as.mu.Lock()
	isl := as.islands[base]
	as.mu.Unlock()
	if isl == nil {
		return false, nil
	}
	valid := func() bool { return !as.released && as.islands[base] == isl }
	return as.installMemSlot(ctx, mm, pc, pageBytes(isl.page), pc-isl.base, valid)
}

// installMemSlot writes a memory slot for the instruction at offset off of
// page. The stub address of that instruction is site. The function then
// replaces the instruction by a branch to the slot, unless valid reports that
// the page does not hold the code of the site any more. The valid function
// runs with as.mu held.
func (as *addressSpace) installMemSlot(ctx context.Context, mm platform.MemoryManager, site uint64, page []byte, off uint64, valid func() bool) (bool, error) {
	as.patchMu.Lock()
	defer as.patchMu.Unlock()
	word := page[off : off+4]
	insn := binary.LittleEndian.Uint32(word)
	if target, ok := decodeBranch(site, insn); ok {
		if meta, found := as.slotAt(target, false); found && meta.site == site && meta.kind == siteMem {
			return true, nil
		}
	}
	acc, ok := classifyMemAccess(insn)
	if !ok {
		return false, nil
	}
	isl, slotOff, slotVA, err := as.allocSlot(ctx, mm, site, memSlotSize)
	if err != nil {
		return false, err
	}
	buf := pageBytes(isl.page)[slotOff:]
	_, body, err := encodeMemSlot(buf, slotVA, site, insn, acc)
	if err != nil {
		return false, err
	}
	meta := slotMeta{site: site, kind: siteMem, reg: acc.base, size: memSlotSize, body: uint8(body)}
	if acc.skipsRestore {
		meta.scratch |= memSkipsRestore
	}
	if acc.fixesValue() {
		meta.scratch |= memFixesValue
	}
	br, err := encodeBranch(site, slotVA)
	if err != nil {
		return false, err
	}
	flushCode(pageBytes(isl.page))
	// The stub task runs on other cores and fetches through its own alias of
	// the island page. patchBlockOnce ends with a protection call on the stub
	// alias after it writes a copy, and the slot follows the same sequence
	// before any thread can branch to it.
	if err := as.syncStubCode(isl.base); err != nil {
		return false, err
	}
	as.mu.Lock()
	if !valid() {
		// The block or the island changed while the Sentry wrote the slot,
		// and the page behind word can belong to another block by now. The
		// thread retries at the site and patches the new copy.
		as.mu.Unlock()
		return true, nil
	}
	isl.slots[slotOff] = meta
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&word[0])), br)
	as.mu.Unlock()
	flushCode(page)
	return true, as.syncStubCode(blockRound(site))
}

// syncStubCode makes the stub task fetch the code that the Sentry wrote to the
// block at base. The Sentry writes through its own alias of the page, and the
// stub fetches through another alias in another address space. The function
// re-applies the read and execute permission on the stub alias, as
// patchBlockOnce does after it writes a copy. It then asks the kernel to
// synchronize the instruction cache for the physical pages of the stub mapping.
func (as *addressSpace) syncStubCode(base uint64) error {
	if err := vmProtect(as.proc.task, base, blockSize, false, vmProtRead|vmProtExecute); err != nil {
		return as.taskErr(err)
	}
	if err := vmSyncCode(as.proc.task, base, blockSize); err != nil {
		return as.taskErr(err)
	}
	return nil
}
