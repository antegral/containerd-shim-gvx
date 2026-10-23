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

	"golang.org/x/sys/unix"
)

// storeToExecBlock handles a write fault into a block that the guest maps
// writable and executable. The site is the stub address of the storing
// instruction, and farGuest is the guest address of the target. It returns
// false when the fault has another cause.
//
// A store from another block restores the writable frame of the target. The
// next fetch from the target patches the code again. A store from the block of
// the target would repeat that cycle forever, because the restored frame has no
// execute permission under the storing instruction. The Sentry runs such a
// store for the guest and writes the bytes to both frames of the block.
func (c *Context) storeToExecBlock(as *addressSpace, sm *sysmsg, site, farGuest uint64) (signalAction, bool) {
	base := blockRound(as.p.stubAddr(farGuest))
	if !as.isWritableExecutable(base) {
		return signalAction{}, false
	}
	if blockRound(site) != base {
		ok, err := as.restoreData(base)
		if err != nil {
			return contextErr(err, unix.ENOMEM), true
		}
		if ok {
			return signalAction{resume: true}, true
		}
		// Another thread restored the block after this thread faulted, so the
		// store retries.
		if st, at, found := as.blockStateOf(base); found && st == blockData && at.Write {
			return signalAction{resume: true}, true
		}
		return signalAction{}, false
	}
	if as.emulateSharedPageStore(sm, site) {
		return signalAction{resume: true}, true
	}
	as.logSelfStore(site, farGuest)
	return signalAction{}, false
}

// emulateSharedPageStore runs the store at the stub address site for a guest
// that stores into the block of the storing instruction. It writes the stored
// bytes to the original frame and to the patched copy, applies the register
// writeback, and moves the thread behind the instruction. It returns false
// when it cannot run the store: for an instruction form that decodeStore does
// not know, for a store that crosses the block, and for a store that overlaps
// an instruction that the patcher changed.
//
// The function holds as.mu while it writes, so a concurrent unmap cannot
// return the patched copy to the page pool under the write.
func (as *addressSpace) emulateSharedPageStore(sm *sysmsg, site uint64) bool {
	base := blockRound(site)
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[base]
	if as.released || blk == nil || blk.state != blockExec || blk.priv == 0 {
		return false
	}
	srcPage := pageBytes(blk.src)
	privPage := pageBytes(blk.priv)
	off := site - base
	st, ok := decodeStore(binary.LittleEndian.Uint32(srcPage[off:]))
	if !ok {
		return false
	}
	check := func(addr uint64, n int) bool {
		stub := as.p.stubAddr(addr)
		if n <= 0 || blockRound(stub) != base || blockRound(stub+uint64(n)-1) != base {
			return false
		}
		for w := (stub - base) &^ 3; w < stub-base+uint64(n); w += 4 {
			if binary.LittleEndian.Uint32(srcPage[w:]) != binary.LittleEndian.Uint32(privPage[w:]) {
				return false // The patcher changed this instruction.
			}
		}
		return true
	}
	write := func(addr uint64, b []byte) {
		o := as.p.stubAddr(addr) - base
		copy(srcPage[o:], b)
		copy(privPage[o:], b)
	}
	regs := storeRegs{ss: &sm.MC.SS, ns: &sm.MC.NS, x18: &sm.X18}
	if _, ok := st.execute(regs, check, write); !ok {
		return false
	}
	sm.MC.SS.PC = site + 4
	return true
}
