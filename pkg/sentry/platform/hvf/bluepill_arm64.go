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
	"encoding/binary"
	"fmt"
	"unsafe"
)

// This file generates the in-guest EL1 exception vector page (the "bluepill"
// of SPEC section 3.2). VBAR_EL1 points at the page. An exception from EL0
// lands in one of the 16 vector slots. The slot code records its index and
// jumps to the common spill routine. The routine stores X0..X30, SP_EL0,
// ELR_EL1, SPSR_EL1, TPIDR_EL0, FAR_EL1, ESR_EL1 and Q0..Q31 into the CommPage
// addressed by SP_EL1, then executes HVC #0. Hypervisor.framework advances PC
// past the HVC, so the next hv_vcpu_run executes the reload routine. The
// reload routine applies the host flush flags, restores every register from
// the CommPage, and returns to EL0 with ERET.

const (
	vectorSlotCount = 16
	vectorSlotSize  = 0x80
	// vectorCommonOffset is the offset of the spill routine in the vector page.
	// The 16 slots of 0x80 bytes fill the first 0x800 bytes of the page.
	vectorCommonOffset = vectorSlotCount * vectorSlotSize
	// vectorReloadOffset is the offset of the reload routine. The HVC
	// instruction of the spill routine sits in the word before it, because
	// Hypervisor.framework resumes at the instruction after HVC.
	vectorReloadOffset = 0x8b8

	// Vector slot numbers as the architecture lays out VBAR_EL1 entries.
	vecCurrentELSPxSync = 4
	vecLowerELSync      = 8
	vecLowerELIRQ       = 9
	vecLowerELSError    = 11
)

// CommPage field offsets used by the stub. The generator takes them from the
// Go struct so the guest code and the host view cannot diverge.
const (
	commOffRegs   = unsafe.Offsetof(CommPage{}.Regs)
	commOffSP     = unsafe.Offsetof(CommPage{}.SP)
	commOffPstate = unsafe.Offsetof(CommPage{}.Pstate)
	commOffFAR    = unsafe.Offsetof(CommPage{}.FaultAddr)
	commOffVector = unsafe.Offsetof(CommPage{}.Vector)
	commOffFlags  = unsafe.Offsetof(CommPage{}.Flags)
	commOffVRegs  = unsafe.Offsetof(CommPage{}.VRegs)
	commOffFPSR   = unsafe.Offsetof(CommPage{}.FPSR)
	commOffFPCR   = unsafe.Offsetof(CommPage{}.FPCR)
)

// Flush flags the host writes into CommPage.Flags.
const (
	flagFlushTLB    = 1 << 0
	flagFlushICache = 1 << 1
)

// Fixed instruction encodings.
const (
	insnHVC0   uint32 = 0xd4000002
	insnERET   uint32 = 0xd69f03e0
	insnDSBISH uint32 = 0xd5033b9f
	insnISB    uint32 = 0xd5033fdf
	// TLBI VMALLE1 invalidates every stage-1 EL1&0 translation of the current
	// VMID, including cached intermediate walk entries.
	insnTLBIVMALLE1 uint32 = 0xd508871f
	// IC IALLUIS invalidates all instruction caches in the inner shareable
	// domain, so it also reaches host cores that ran this vCPU earlier.
	insnICIALLUIS uint32 = 0xd508711f
)

// sysReg is an AArch64 system register encoding for MRS and MSR.
type sysReg uint32

func mkSysReg(op0, op1, crn, crm, op2 uint32) sysReg {
	return sysReg((op0&1)<<19 | op1<<16 | crn<<12 | crm<<8 | op2<<5)
}

var (
	sysRegSPEL0    = mkSysReg(3, 0, 4, 1, 0)
	sysRegELREL1   = mkSysReg(3, 0, 4, 0, 1)
	sysRegSPSREL1  = mkSysReg(3, 0, 4, 0, 0)
	sysRegTPIDREL0 = mkSysReg(3, 3, 13, 0, 2)
	sysRegFAREL1   = mkSysReg(3, 0, 6, 0, 0)
	sysRegESREL1   = mkSysReg(3, 0, 5, 2, 0)
	sysRegFPSR     = mkSysReg(3, 3, 4, 4, 1)
	sysRegFPCR     = mkSysReg(3, 3, 4, 4, 0)
)

func encMRS(sr sysReg, rt uint32) uint32 { return 0xd5300000 | uint32(sr) | rt }
func encMSR(sr sysReg, rt uint32) uint32 { return 0xd5100000 | uint32(sr) | rt }

func encMOVZ(rd, imm16 uint32) uint32 { return 0xd2800000 | imm16<<5 | rd }

// encB encodes an unconditional branch by a byte displacement.
func encB(byteOff int) uint32 { return 0x14000000 | uint32(byteOff/4)&0x03ffffff }

// encCBZ encodes CBZ Xt with a byte displacement.
func encCBZ(rt uint32, byteOff int) uint32 {
	return 0xb4000000 | (uint32(byteOff/4)&0x7ffff)<<5 | rt
}

// encTBZ encodes TBZ Xt, #bit with a byte displacement. Bit must be below 32.
func encTBZ(rt, bit uint32, byteOff int) uint32 {
	return 0x36000000 | bit<<19 | (uint32(byteOff/4)&0x3fff)<<5 | rt
}

// Load and store encodings use SP as the base register (register number 31).
func encLDRX(rt uint32, off uintptr) uint32 {
	return 0xf9400000 | uint32(off/8)<<10 | 31<<5 | rt
}

func encSTRX(rt uint32, off uintptr) uint32 {
	return 0xf9000000 | uint32(off/8)<<10 | 31<<5 | rt
}

func encPairX(load bool, rt1, rt2 uint32, off uintptr) uint32 {
	base := uint32(0xa9000000)
	if load {
		base = 0xa9400000
	}
	return base | (uint32(off/8)&0x7f)<<15 | rt2<<10 | 31<<5 | rt1
}

func encPairQ(load bool, rt1, rt2 uint32, off uintptr) uint32 {
	base := uint32(0xad000000)
	if load {
		base = 0xad400000
	}
	return base | (uint32(off/16)&0x7f)<<15 | rt2<<10 | 31<<5 | rt1
}

// stubBuilder appends instructions to the vector page.
type stubBuilder struct {
	page []byte
	off  int
}

func (b *stubBuilder) emit(insn uint32) {
	binary.LittleEndian.PutUint32(b.page[b.off:b.off+4], insn)
	b.off += 4
}

func (b *stubBuilder) emitAll(insns ...uint32) {
	for _, insn := range insns {
		b.emit(insn)
	}
}

// spillGPRs stores X2..X30 into CommPage.Regs. Slot code stored X0 and X1.
func (b *stubBuilder) spillGPRs() {
	for k := uint32(1); k <= 14; k++ {
		b.emit(encPairX(false, 2*k, 2*k+1, commOffRegs+uintptr(16*k)))
	}
	b.emit(encSTRX(30, commOffRegs+30*8))
}

func (b *stubBuilder) reloadGPRs() {
	for k := uint32(0); k <= 14; k++ {
		b.emit(encPairX(true, 2*k, 2*k+1, commOffRegs+uintptr(16*k)))
	}
	b.emit(encLDRX(30, commOffRegs+30*8))
}

// buildVectorPage returns the 4KB EL1 vector page. It panics when the
// generated code does not match the layout constants: the stub is static data
// and a mismatch is a programming error.
func buildVectorPage() []byte {
	page := make([]byte, 4096)
	b := &stubBuilder{page: page}

	for slot := uint32(0); slot < vectorSlotCount; slot++ {
		b.off = int(slot) * vectorSlotSize
		b.emit(encPairX(false, 0, 1, commOffRegs))
		b.emit(encMOVZ(0, slot))
		b.emit(encSTRX(0, commOffVector))
		b.emit(encB(vectorCommonOffset - b.off))
	}

	b.off = vectorCommonOffset
	b.spillGPRs()
	b.emitAll(
		encMRS(sysRegSPEL0, 0),
		encMRS(sysRegELREL1, 1),
		encMRS(sysRegSPSREL1, 2),
		encMRS(sysRegTPIDREL0, 3),
		encMRS(sysRegFAREL1, 4),
		encMRS(sysRegESREL1, 5),
		encPairX(false, 0, 1, commOffSP),
		encPairX(false, 2, 3, commOffPstate),
		encPairX(false, 4, 5, commOffFAR),
	)
	// The V registers are spilled on every exit. A vCPU serves many Contexts,
	// so the registers cannot stay in hardware between Switch calls.
	for k := uint32(0); k < 16; k++ {
		b.emit(encPairQ(false, 2*k, 2*k+1, commOffVRegs+uintptr(32*k)))
	}
	b.emitAll(
		encMRS(sysRegFPSR, 0),
		encMRS(sysRegFPCR, 1),
		encSTRX(0, commOffFPSR),
		encSTRX(1, commOffFPCR),
		insnDSBISH,
		insnHVC0,
	)
	if b.off != vectorReloadOffset {
		panic(fmt.Sprintf("hvf: vector spill routine ends at %#x, want %#x", b.off, vectorReloadOffset))
	}

	// Reload routine. Flags is zero in the common case, so the fast path
	// skips every cache maintenance instruction.
	b.emit(encLDRX(0, commOffFlags))
	// The first CBZ jumps over the flush block: CBZ, TBZ, TLBI, TBZ, IC, DSB, ISB.
	b.emit(encCBZ(0, 7*4))
	b.emit(encTBZ(0, 0, 2*4))
	b.emit(insnTLBIVMALLE1)
	b.emit(encTBZ(0, 1, 2*4))
	b.emit(insnICIALLUIS)
	b.emit(insnDSBISH)
	b.emit(insnISB)
	b.emitAll(
		encLDRX(0, commOffFPSR),
		encLDRX(1, commOffFPCR),
		encMSR(sysRegFPSR, 0),
		encMSR(sysRegFPCR, 1),
	)
	for k := uint32(0); k < 16; k++ {
		b.emit(encPairQ(true, 2*k, 2*k+1, commOffVRegs+uintptr(32*k)))
	}
	b.emitAll(
		encPairX(true, 0, 1, commOffSP),
		encPairX(true, 2, 3, commOffPstate),
		encMSR(sysRegSPEL0, 0),
		encMSR(sysRegELREL1, 1),
		encMSR(sysRegSPSREL1, 2),
		encMSR(sysRegTPIDREL0, 3),
	)
	b.reloadGPRs()
	b.emit(insnERET)
	return page
}
