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
	"encoding/binary"
	"fmt"

	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// This file generates the EL1 code that runs inside an arm64 partition.
//
// Every slot of the exception vector table loads the slot number and branches
// to Common. SP_EL1 always equals the CommPage address of the virtual
// processor, so the handler addresses CommPage through SP without a scratch
// register. Common spills X0 to X30, SP_EL0, ELR_EL1, SPSR_EL1, TPIDR_EL0,
// FAR_EL1 and ESR_EL1, writes ExitException and executes HVC #0. The Sentry
// resumes the virtual processor at Reload, which restores the system
// registers and the general registers and returns with ERET.

// Vector table slot numbers in architectural order.
const (
	a64SlotCurSP0Sync = 0
	a64SlotCurSPxSync = hvcommon.SlotCurrentSPxSync
	a64SlotLowA64Sync = hvcommon.SlotLowerSync
	a64SlotLowA64IRQ  = hvcommon.SlotLowerIRQ
	a64SlotLowA64FIQ  = 10
	a64SlotLowA64SErr = hvcommon.SlotLowerSError
	a64SlotLowA32Sync = 12
	a64VectorSlots    = hvcommon.VectorSlots
	a64VectorSlotSize = hvcommon.VectorSlotSize
	a64CodeOffVectors = 0x000
	a64CodeOffCommon  = hvcommon.VectorCommonOffset
	a64PstateKernel   = hvcommon.PstateEL1h
	a64PstateModeMask = 0xF
	a64PstateUserMask = 0x3CF // Bits that a user-mode PSTATE must keep clear.
)

// MAIR_EL1 attribute bytes. Index 0 must be Normal write-back because
// hostarch.MemoryTypeWriteBack is zero and PTE attribute index 0 selects it.
const (
	a64MairNormal   = hvcommon.MAIRNormalWB
	a64MairNormalNC = 0x44
	a64MairDevice   = 0x00

	// a64Mair mirrors the MAIR_EL1 value of the KVM platform.
	a64Mair = a64MairNormal | a64MairNormalNC<<8 | a64MairDevice<<16

	// a64SctlrSet lists the SCTLR_EL1 bits that bring-up turns on. They
	// match the KVM platform: MMU, data cache, instruction cache, DC ZVA at
	// EL0 and CTR_EL0 and cache maintenance at EL0. Bring-up reads the
	// register first, so reserved-to-one bits keep their reset value.
	a64SctlrM   = 1 << 0
	a64SctlrC   = 1 << 2
	a64SctlrI   = 1 << 12
	a64SctlrDZE = 1 << 14
	a64SctlrUCT = 1 << 15
	a64SctlrUCI = 1 << 26
	a64SctlrSet = a64SctlrM | a64SctlrC | a64SctlrI | a64SctlrDZE | a64SctlrUCT | a64SctlrUCI

	a64CpacrNoTrap = hvcommon.CPACRNoTrap
	a64CntkctlEL0  = hvcommon.CNTKCTLEL0
)

// a64TCR configures 48-bit translation for both halves with 4KB granules,
// inner-shareable write-back write-allocate walks, a 36-bit physical address
// size (IPS 1), and top-byte-ignore for TTBR0.
var a64TCR = hvcommon.TCR(1)

// a64Stubs is the generated arm64 guest code.
type a64Stubs struct {
	// Code is the stub code page. The vector table starts at offset 0 and
	// is 2KB aligned, as VBAR_EL1 requires.
	Code []byte

	Vectors   int
	Common    int
	Hvc       int
	Reload    int
	ReloadEnd int
}

// buildA64Stubs generates the stub code page.
func buildA64Stubs() (*a64Stubs, error) {
	s := &a64Stubs{
		Code:    make([]byte, pageSize),
		Vectors: a64CodeOffVectors,
		Common:  a64CodeOffCommon,
	}

	// Vector table: save X0 and X1, load the slot number, branch to Common.
	for slot := range a64VectorSlots {
		a := newA64Asm()
		a.stpSP(0, 1, 0)
		a.movz(0, uint16(slot))
		base := a64CodeOffVectors + slot*a64VectorSlotSize
		a.bAbs(int32(a64CodeOffCommon - (base + a.pos())))
		code, err := a.finish()
		if err != nil {
			return nil, fmt.Errorf("whpx: assemble vector slot %d: %w", slot, err)
		}
		copy(s.Code[base:], code)
	}

	a := newA64Asm()
	// Spill X2 to X30 and the system registers.
	a.strSP(0, commOffVector)
	for r := 2; r < 30; r += 2 {
		a.stpSP(r, r+1, commOffRegs+r*8)
	}
	a.strSP(30, commOffRegs+30*8)
	a.mrs(0, hvcommon.SysRegSPEL0)
	a.mrs(1, hvcommon.SysRegELREL1)
	a.mrs(2, hvcommon.SysRegSPSREL1)
	a.mrs(3, hvcommon.SysRegTPIDREL0)
	a.mrs(4, hvcommon.SysRegFAREL1)
	a.mrs(5, hvcommon.SysRegESREL1)
	a.stpSP(0, 1, commOffSP)
	a.stpSP(2, 3, commOffPstate)
	a.stpSP(4, 5, commOffFaultAddr)
	a.movzW(0, uint16(ExitException))
	a.strWSP(0, commOffExitReason)
	hvc := a.pos()
	a.hvc(0)

	// Reload path. HVC returns here, and the Sentry can also start here.
	reload := a.pos()
	a.ldpSP(0, 1, commOffSP)
	a.ldpSP(2, 3, commOffPstate)
	a.msr(hvcommon.SysRegSPEL0, 0)
	a.msr(hvcommon.SysRegELREL1, 1)
	a.msr(hvcommon.SysRegSPSREL1, 2)
	a.msr(hvcommon.SysRegTPIDREL0, 3)
	a.ldrWSP(0, commOffFlags)
	a.tbz(0, 0, "noroot")
	a.ldrSP(1, commOffRoot)
	a.msr(hvcommon.SysRegTTBR0EL1, 1)
	a.isb()
	a.tlbiVMALLE1()
	a.dsbNSH()
	a.isb()
	a.label("noroot")
	a.tbz(0, 2, "noicache")
	a.icIALLUIS()
	a.dsbISH()
	a.isb()
	a.label("noicache")
	for r := 2; r < 30; r += 2 {
		a.ldpSP(r, r+1, commOffRegs+r*8)
	}
	a.ldrSP(30, commOffRegs+30*8)
	a.ldpSP(0, 1, commOffRegs)
	a.eret()
	reloadEnd := a.pos()

	code, err := a.finish()
	if err != nil {
		return nil, fmt.Errorf("whpx: assemble common handler: %w", err)
	}
	if a64CodeOffCommon+len(code) > pageSize {
		return nil, fmt.Errorf("whpx: common handler is %d bytes and overflows the page", len(code))
	}
	copy(s.Code[a64CodeOffCommon:], code)
	s.Hvc = a64CodeOffCommon + hvc
	s.Reload = a64CodeOffCommon + reload
	s.ReloadEnd = a64CodeOffCommon + reloadEnd
	return s, nil
}

// a64Asm assembles the AArch64 subset that the stub uses.
type a64Asm struct {
	words  []uint32
	labels map[string]int
	fixups []a64Fixup
}

type a64Fixup struct {
	at    int
	label string
	kind  byte
}

func newA64Asm() *a64Asm { return &a64Asm{labels: make(map[string]int)} }

// pos returns the byte offset of the next instruction.
func (a *a64Asm) pos() int { return len(a.words) * 4 }

func (a *a64Asm) emit(w uint32) { a.words = append(a.words, w) }

func (a *a64Asm) label(name string) { a.labels[name] = len(a.words) }

// stpSP emits STP Xt1, Xt2, [SP, #off].
func (a *a64Asm) stpSP(t1, t2, off int) { a.emit(hvcommon.STPXSP(t1, t2, off)) }

// ldpSP emits LDP Xt1, Xt2, [SP, #off].
func (a *a64Asm) ldpSP(t1, t2, off int) { a.emit(hvcommon.LDPXSP(t1, t2, off)) }

// strSP emits STR Xt, [SP, #off].
func (a *a64Asm) strSP(t, off int) { a.emit(hvcommon.STRXSP(t, off)) }

// ldrSP emits LDR Xt, [SP, #off].
func (a *a64Asm) ldrSP(t, off int) { a.emit(hvcommon.LDRXSP(t, off)) }

// strWSP emits STR Wt, [SP, #off].
func (a *a64Asm) strWSP(t, off int) { a.emit(hvcommon.STRWSP(t, off)) }

// ldrWSP emits LDR Wt, [SP, #off].
func (a *a64Asm) ldrWSP(t, off int) { a.emit(hvcommon.LDRWSP(t, off)) }

// movz emits MOVZ Xd, #imm.
func (a *a64Asm) movz(d int, imm uint16) { a.emit(hvcommon.MOVZ(d, imm)) }

// movzW emits MOVZ Wd, #imm.
func (a *a64Asm) movzW(d int, imm uint16) { a.emit(hvcommon.MOVZW(d, imm)) }

// mrs emits MRS Xt, reg.
func (a *a64Asm) mrs(t int, r hvcommon.SysReg) { a.emit(hvcommon.MRS(t, r)) }

// msr emits MSR reg, Xt.
func (a *a64Asm) msr(r hvcommon.SysReg, t int) { a.emit(hvcommon.MSR(r, t)) }

// bAbs emits B with a byte displacement from this instruction.
func (a *a64Asm) bAbs(disp int32) { a.emit(hvcommon.B(int(disp))) }

// tbz emits TBZ Wt, #bit, label.
func (a *a64Asm) tbz(t, bit int, label string) {
	a.fixups = append(a.fixups, a64Fixup{at: len(a.words), label: label, kind: 'z'})
	a.emit(hvcommon.TBZ(t, bit, 0))
}

func (a *a64Asm) hvc(imm uint16) { a.emit(hvcommon.HVC(imm)) }
func (a *a64Asm) eret()          { a.emit(hvcommon.ERET) }
func (a *a64Asm) isb()           { a.emit(hvcommon.ISB) }
func (a *a64Asm) dsbNSH()        { a.emit(hvcommon.DSBNSH) }
func (a *a64Asm) dsbISH()        { a.emit(hvcommon.DSBISH) }
func (a *a64Asm) tlbiVMALLE1()   { a.emit(hvcommon.TLBIVMALLE1) }
func (a *a64Asm) icIALLUIS()     { a.emit(hvcommon.ICIALLUIS) }

// finish resolves the branches and returns the code.
func (a *a64Asm) finish() ([]byte, error) {
	for _, f := range a.fixups {
		target, ok := a.labels[f.label]
		if !ok {
			return nil, fmt.Errorf("undefined label %q", f.label)
		}
		rel := target - f.at
		if rel < -(1<<13) || rel >= 1<<13 {
			return nil, fmt.Errorf("branch to %q is out of range", f.label)
		}
		a.words[f.at] |= (uint32(rel) & 0x3FFF) << 5
	}
	out := make([]byte, len(a.words)*4)
	for i, w := range a.words {
		binary.LittleEndian.PutUint32(out[i*4:], w)
	}
	return out, nil
}
