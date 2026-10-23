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

	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
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
	vectorSlotCount = hvcommon.VectorSlots
	vectorSlotSize  = hvcommon.VectorSlotSize
	// vectorCommonOffset is the offset of the spill routine in the vector page.
	// The 16 slots of 0x80 bytes fill the first 0x800 bytes of the page.
	vectorCommonOffset = hvcommon.VectorCommonOffset
	// vectorReloadOffset is the offset of the reload routine. The HVC
	// instruction of the spill routine sits in the word before it, because
	// Hypervisor.framework resumes at the instruction after HVC.
	vectorReloadOffset = 0x8b8

	// Vector slot numbers as the architecture lays out VBAR_EL1 entries.
	vecCurrentELSPxSync = hvcommon.SlotCurrentSPxSync
	vecLowerELSync      = hvcommon.SlotLowerSync
	vecLowerELIRQ       = hvcommon.SlotLowerIRQ
	vecLowerELSError    = hvcommon.SlotLowerSError
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
	for k := 1; k <= 14; k++ {
		b.emit(hvcommon.STPXSP(2*k, 2*k+1, int(commOffRegs)+16*k))
	}
	b.emit(hvcommon.STRXSP(30, int(commOffRegs)+30*8))
}

func (b *stubBuilder) reloadGPRs() {
	for k := 0; k <= 14; k++ {
		b.emit(hvcommon.LDPXSP(2*k, 2*k+1, int(commOffRegs)+16*k))
	}
	b.emit(hvcommon.LDRXSP(30, int(commOffRegs)+30*8))
}

// buildVectorPage returns the 4KB EL1 vector page. It panics when the
// generated code does not match the layout constants: the stub is static data
// and a mismatch is a programming error.
func buildVectorPage() []byte {
	page := make([]byte, 4096)
	b := &stubBuilder{page: page}

	for slot := 0; slot < vectorSlotCount; slot++ {
		b.off = slot * vectorSlotSize
		b.emit(hvcommon.STPXSP(0, 1, int(commOffRegs)))
		b.emit(hvcommon.MOVZ(0, uint16(slot)))
		b.emit(hvcommon.STRXSP(0, int(commOffVector)))
		b.emit(hvcommon.B(vectorCommonOffset - b.off))
	}

	b.off = vectorCommonOffset
	b.spillGPRs()
	b.emitAll(
		hvcommon.MRS(0, hvcommon.SysRegSPEL0),
		hvcommon.MRS(1, hvcommon.SysRegELREL1),
		hvcommon.MRS(2, hvcommon.SysRegSPSREL1),
		hvcommon.MRS(3, hvcommon.SysRegTPIDREL0),
		hvcommon.MRS(4, hvcommon.SysRegFAREL1),
		hvcommon.MRS(5, hvcommon.SysRegESREL1),
		hvcommon.STPXSP(0, 1, int(commOffSP)),
		hvcommon.STPXSP(2, 3, int(commOffPstate)),
		hvcommon.STPXSP(4, 5, int(commOffFAR)),
	)
	// The V registers are spilled on every exit. A vCPU serves many Contexts,
	// so the registers cannot stay in hardware between Switch calls.
	for k := 0; k < 16; k++ {
		b.emit(hvcommon.STPQSP(2*k, 2*k+1, int(commOffVRegs)+32*k))
	}
	b.emitAll(
		hvcommon.MRS(0, hvcommon.SysRegFPSR),
		hvcommon.MRS(1, hvcommon.SysRegFPCR),
		hvcommon.STRXSP(0, int(commOffFPSR)),
		hvcommon.STRXSP(1, int(commOffFPCR)),
		hvcommon.DSBISH,
		hvcommon.HVC(0),
	)
	if b.off != vectorReloadOffset {
		panic(fmt.Sprintf("hvf: vector spill routine ends at %#x, want %#x", b.off, vectorReloadOffset))
	}

	// Reload routine. Flags is zero in the common case, so the fast path
	// skips every cache maintenance instruction.
	b.emit(hvcommon.LDRXSP(0, int(commOffFlags)))
	// The first CBZ jumps over the flush block: CBZ, TBZ, TLBI, TBZ, IC, DSB, ISB.
	b.emit(hvcommon.CBZ(0, 7*4))
	b.emit(hvcommon.TBZ(0, 0, 2*4))
	b.emit(hvcommon.TLBIVMALLE1)
	b.emit(hvcommon.TBZ(0, 1, 2*4))
	b.emit(hvcommon.ICIALLUIS)
	b.emit(hvcommon.DSBISH)
	b.emit(hvcommon.ISB)
	b.emitAll(
		hvcommon.LDRXSP(0, int(commOffFPSR)),
		hvcommon.LDRXSP(1, int(commOffFPCR)),
		hvcommon.MSR(hvcommon.SysRegFPSR, 0),
		hvcommon.MSR(hvcommon.SysRegFPCR, 1),
	)
	for k := 0; k < 16; k++ {
		b.emit(hvcommon.LDPQSP(2*k, 2*k+1, int(commOffVRegs)+32*k))
	}
	b.emitAll(
		hvcommon.LDPXSP(0, 1, int(commOffSP)),
		hvcommon.LDPXSP(2, 3, int(commOffPstate)),
		hvcommon.MSR(hvcommon.SysRegSPEL0, 0),
		hvcommon.MSR(hvcommon.SysRegELREL1, 1),
		hvcommon.MSR(hvcommon.SysRegSPSREL1, 2),
		hvcommon.MSR(hvcommon.SysRegTPIDREL0, 3),
	)
	b.reloadGPRs()
	b.emit(hvcommon.ERET)
	return page
}
