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
)

// This file generates the ring-0 code that runs inside an amd64 partition.
//
// SYSCALL enters x64Stubs.Entry through MSR_LSTAR. The entry code swaps GS to
// the per-VP CommPage, spills the registers, writes ExitSyscall and halts.
// Exceptions enter through the IDT stubs and reach Common, which spills the
// vector, error code, CR2 and the interrupt frame before it halts. The Sentry
// then resumes the virtual processor at Reload, which writes CR3 when asked,
// loads the registers and returns with SYSRETQ or IRETQ.
//
// The code addresses CommPage through the GS segment. KernelGsBase holds the
// CommPage address while user code runs, so SWAPGS exchanges it with the user
// GS base on every entry and exit.

// Segment selectors of the guest GDT. They follow the Linux x86-64 layout, so
// the user selectors equal the values that pkg/sentry/arch expects.
const (
	x64SelKernelCS32 = 0x08
	x64SelKernelCS   = 0x10
	x64SelKernelSS   = 0x18
	x64SelUserCS32   = 0x23
	x64SelUserSS     = 0x2B
	x64SelUserCS     = 0x33

	// x64StarUserBase is the SYSRET selector base. SYSRET adds 8 for SS and
	// 16 for the 64-bit CS.
	x64StarUserBase = x64SelUserCS32

	// x64SelTR is the task register selector. The value indexes past the GDT
	// limit because every virtual processor loads its own hidden TSS state.
	x64SelTR = 0x38

	// x64GDTLimit covers the seven descriptors of the guest GDT.
	x64GDTLimit = 0x37

	// x64IDTVectors counts the IDT entries. Vectors above it raise #GP.
	x64IDTVectors = 32
	x64IDTLimit   = x64IDTVectors*16 - 1

	// x64SfMask clears TF, IF, DF, IOPL, NT and AC on SYSCALL entry.
	x64SfMask = 0x47700
)

// Offsets inside the stub code page.
const (
	x64CodeOffEntry     = 0x000
	x64CodeOffReload    = 0x200
	x64CodeOffExcStubs  = 0x600
	x64CodeOffCommon    = 0x800
	x64ExcStubSize      = 16
	x64SysOffGDT        = 0x000
	x64SysOffIDT        = 0x100
	x64DescAttrCode64   = 0x00AF9B000000FFFF
	x64DescAttrCode32   = 0x00CF9B000000FFFF
	x64DescAttrData     = 0x00CF93000000FFFF
	x64DescAttrUCode32  = 0x00CFFB000000FFFF
	x64DescAttrUData    = 0x00CFF3000000FFFF
	x64DescAttrUCode64  = 0x00AFFB000000FFFF
	x64IDTGateInterrupt = 0x8E
)

// x64Regs lists the general registers that CommPage.Regs spills, as hardware
// register numbers. RSP has its own slot.
var x64Regs = [...]int{0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// x64ErrorCodeVectors lists the vectors for which the CPU pushes an error code.
var x64ErrorCodeVectors = map[int]bool{8: true, 10: true, 11: true, 12: true, 13: true, 14: true, 17: true, 21: true, 29: true, 30: true}

// x64Stubs is the generated amd64 guest code and tables.
type x64Stubs struct {
	// Code and Sys are the page images for the code page and the GDT/IDT page.
	Code []byte
	Sys  []byte

	// Offsets inside Code.
	Entry     int
	EntryEnd  int
	Reload    int
	ReloadEnd int
	Common    int
	CommonEnd int
	ExcStubs  int

	// Hlt holds the offsets of the three HLT instructions.
	HltSyscall   int
	HltException int
	HltKernel    int
}

// buildX64Stubs generates the stub pages for a kernel region that starts at
// kernelBase.
func buildX64Stubs(kernelBase uint64) (*x64Stubs, error) {
	layout := newKernelLayout(false)
	layout.base = kernelBase
	s := &x64Stubs{
		Code:     make([]byte, pageSize),
		Sys:      make([]byte, pageSize),
		Entry:    x64CodeOffEntry,
		Reload:   x64CodeOffReload,
		Common:   x64CodeOffCommon,
		ExcStubs: x64CodeOffExcStubs,
	}

	// Syscall entry.
	a := newX86Asm()
	a.swapgs()
	a.movGSFromReg(commOffSP, 4)
	a.movRegFromGS(4, commOffRegs+4*8)
	for _, r := range x64Regs {
		a.movGSFromReg(commOffRegs+int32(r)*8, r)
	}
	a.movGSImm32(commOffExitReason, uint32(ExitSyscall))
	s.HltSyscall = x64CodeOffEntry + a.pos()
	a.hlt()
	entry, err := a.finish()
	if err != nil {
		return nil, fmt.Errorf("whpx: assemble syscall entry: %w", err)
	}
	if len(entry) > x64CodeOffReload-x64CodeOffEntry {
		return nil, fmt.Errorf("whpx: syscall entry is %d bytes and overlaps the reload code", len(entry))
	}
	copy(s.Code[x64CodeOffEntry:], entry)
	s.EntryEnd = x64CodeOffEntry + len(entry)

	// Reload path.
	a = newX86Asm()
	a.testGSImm32(commOffFlags, flagReloadRoot)
	a.jcc32(x86CondZ, "noroot")
	a.movRegFromGS(0, commOffRoot)
	a.movCR3FromRAX()
	a.label("noroot")
	a.testGSImm32(commOffFlags, flagFullRestore)
	a.jcc32(x86CondNZ, "iret")
	for _, r := range x64Regs {
		a.movRegFromGS(r, commOffRegs+int32(r)*8)
	}
	a.movRegFromGS(4, commOffSP)
	a.swapgs()
	a.sysretq()
	a.label("iret")
	a.movRegFromGS(4, commOffRegs+4*8)
	a.pushGS(commOffSS)
	a.pushGS(commOffSP)
	a.pushGS(commOffPstate)
	a.pushGS(commOffCS)
	a.pushGS(commOffPC)
	for _, r := range x64Regs {
		a.movRegFromGS(r, commOffRegs+int32(r)*8)
	}
	a.swapgs()
	a.iretq()
	reload, err := a.finish()
	if err != nil {
		return nil, fmt.Errorf("whpx: assemble reload path: %w", err)
	}
	if len(reload) > x64CodeOffExcStubs-x64CodeOffReload {
		return nil, fmt.Errorf("whpx: reload path is %d bytes and overlaps the exception stubs", len(reload))
	}
	copy(s.Code[x64CodeOffReload:], reload)
	s.ReloadEnd = x64CodeOffReload + len(reload)

	// Exception stubs.
	for v := range x64IDTVectors {
		stub := newX86Asm()
		if !x64ErrorCodeVectors[v] {
			stub.pushImm8(0)
		}
		stub.pushImm8(byte(v))
		off := x64CodeOffExcStubs + v*x64ExcStubSize
		rel := int32(x64CodeOffCommon) - int32(off+stub.pos()+5)
		stub.jmpRel32(rel)
		code, err := stub.finish()
		if err != nil {
			return nil, fmt.Errorf("whpx: assemble exception stub %d: %w", v, err)
		}
		if len(code) > x64ExcStubSize {
			return nil, fmt.Errorf("whpx: exception stub %d is %d bytes", v, len(code))
		}
		copy(s.Code[off:], code)
		for i := off + len(code); i < off+x64ExcStubSize; i++ {
			s.Code[i] = 0xCC
		}
	}

	// Common exception path.
	a = newX86Asm()
	a.testRSPByte(24, 3)
	a.jcc32(x86CondZ, "spill")
	a.swapgs()
	a.label("spill")
	for _, r := range x64Regs {
		a.movGSFromReg(commOffRegs+int32(r)*8, r)
	}
	for _, off := range []int32{commOffVector, commOffFaultCode, commOffPC, commOffCS, commOffPstate, commOffSP, commOffSS} {
		a.popRAX()
		a.movGSFromReg(off, 0)
	}
	a.movRAXFromCR2()
	a.movGSFromReg(commOffFaultAddr, 0)
	a.testGSImm32(commOffCS, 3)
	a.jcc32(x86CondZ, "kernel")
	a.movGSImm32(commOffExitReason, uint32(ExitException))
	s.HltException = x64CodeOffCommon + a.pos()
	a.hlt()
	a.label("kernel")
	a.movGSImm32(commOffExitReason, uint32(ExitKernelFault))
	s.HltKernel = x64CodeOffCommon + a.pos()
	a.hlt()
	common, err := a.finish()
	if err != nil {
		return nil, fmt.Errorf("whpx: assemble common exception path: %w", err)
	}
	if x64CodeOffCommon+len(common) > pageSize {
		return nil, fmt.Errorf("whpx: common exception path is %d bytes and overflows the page", len(common))
	}
	copy(s.Code[x64CodeOffCommon:], common)
	s.CommonEnd = x64CodeOffCommon + len(common)

	// GDT.
	gdt := s.Sys[x64SysOffGDT:]
	for i, d := range []uint64{
		0,
		x64DescAttrCode32,
		x64DescAttrCode64,
		x64DescAttrData,
		x64DescAttrUCode32,
		x64DescAttrUData,
		x64DescAttrUCode64,
	} {
		binary.LittleEndian.PutUint64(gdt[i*8:], d)
	}

	// IDT. Every gate is an interrupt gate with DPL 0, so INT n from user
	// mode raises #GP like a kernel without 32-bit emulation.
	idt := s.Sys[x64SysOffIDT:]
	for v := range x64IDTVectors {
		target := layout.code() + uint64(x64CodeOffExcStubs+v*x64ExcStubSize)
		g := idt[v*16:]
		binary.LittleEndian.PutUint16(g[0:], uint16(target))
		binary.LittleEndian.PutUint16(g[2:], x64SelKernelCS)
		g[4] = 0
		g[5] = x64IDTGateInterrupt
		binary.LittleEndian.PutUint16(g[6:], uint16(target>>16))
		binary.LittleEndian.PutUint32(g[8:], uint32(target>>32))
	}
	return s, nil
}

// x64InitTSS writes the task state segment of one virtual processor into its
// CommPage. Only RSP0 and the I/O map base are meaningful.
func x64InitTSS(page *CommPage, commVA uint64) {
	binary.LittleEndian.PutUint64(page.TSS[4:], commVA+commStackTop)
	binary.LittleEndian.PutUint16(page.TSS[102:], commTSSSize)
}

// x86Cond is the low nibble of a Jcc opcode.
type x86Cond byte

const (
	x86CondZ  x86Cond = 0x4
	x86CondNZ x86Cond = 0x5
)

// x86Asm assembles the small instruction subset that the stubs use.
type x86Asm struct {
	buf    []byte
	labels map[string]int
	fixups []x86Fixup
}

type x86Fixup struct {
	at    int
	label string
}

func newX86Asm() *x86Asm {
	return &x86Asm{labels: make(map[string]int)}
}

func (a *x86Asm) pos() int { return len(a.buf) }

func (a *x86Asm) emit(b ...byte) { a.buf = append(a.buf, b...) }

func (a *x86Asm) emit32(v uint32) {
	a.buf = binary.LittleEndian.AppendUint32(a.buf, v)
}

func (a *x86Asm) label(name string) { a.labels[name] = len(a.buf) }

// gsMem emits the GS prefix, the ModRM and SIB bytes for an absolute address
// and the displacement. reg is the ModRM reg field.
func (a *x86Asm) gsMem(reg byte, disp int32) {
	a.emit(0x04|(reg&7)<<3, 0x25)
	a.emit32(uint32(disp))
}

// movGSFromReg emits MOV [gs:disp], r64.
func (a *x86Asm) movGSFromReg(disp int32, reg int) {
	a.emit(0x65, 0x48|byte(reg>>3)<<2, 0x89)
	a.gsMem(byte(reg), disp)
}

// movRegFromGS emits MOV r64, [gs:disp].
func (a *x86Asm) movRegFromGS(reg int, disp int32) {
	a.emit(0x65, 0x48|byte(reg>>3)<<2, 0x8B)
	a.gsMem(byte(reg), disp)
}

// movGSImm32 emits MOV DWORD [gs:disp], imm32.
func (a *x86Asm) movGSImm32(disp int32, imm uint32) {
	a.emit(0x65, 0xC7)
	a.gsMem(0, disp)
	a.emit32(imm)
}

// testGSImm32 emits TEST DWORD [gs:disp], imm32.
func (a *x86Asm) testGSImm32(disp int32, imm uint32) {
	a.emit(0x65, 0xF7)
	a.gsMem(0, disp)
	a.emit32(imm)
}

// pushGS emits PUSH QWORD [gs:disp].
func (a *x86Asm) pushGS(disp int32) {
	a.emit(0x65, 0xFF)
	a.gsMem(6, disp)
}

// testRSPByte emits TEST BYTE [rsp+disp8], imm8.
func (a *x86Asm) testRSPByte(disp int8, imm byte) {
	a.emit(0xF6, 0x44, 0x24, byte(disp), imm)
}

func (a *x86Asm) pushImm8(v byte) { a.emit(0x6A, v) }
func (a *x86Asm) popRAX()         { a.emit(0x58) }
func (a *x86Asm) hlt()            { a.emit(0xF4) }
func (a *x86Asm) swapgs()         { a.emit(0x0F, 0x01, 0xF8) }
func (a *x86Asm) sysretq()        { a.emit(0x48, 0x0F, 0x07) }
func (a *x86Asm) iretq()          { a.emit(0x48, 0xCF) }
func (a *x86Asm) movCR3FromRAX()  { a.emit(0x0F, 0x22, 0xD8) }
func (a *x86Asm) movRAXFromCR2()  { a.emit(0x0F, 0x20, 0xD0) }
func (a *x86Asm) jmpRel32(rel int32) {
	a.emit(0xE9)
	a.emit32(uint32(rel))
}

// jcc32 emits a conditional jump with a 32-bit displacement to a label.
func (a *x86Asm) jcc32(cond x86Cond, label string) {
	a.emit(0x0F, 0x80|byte(cond))
	a.fixups = append(a.fixups, x86Fixup{at: len(a.buf), label: label})
	a.emit32(0)
}

// finish resolves the jumps and returns the code.
func (a *x86Asm) finish() ([]byte, error) {
	for _, f := range a.fixups {
		target, ok := a.labels[f.label]
		if !ok {
			return nil, fmt.Errorf("undefined label %q", f.label)
		}
		binary.LittleEndian.PutUint32(a.buf[f.at:], uint32(int32(target-(f.at+4))))
	}
	return a.buf, nil
}
