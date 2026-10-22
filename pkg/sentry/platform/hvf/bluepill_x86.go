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

// This file generates the in-guest Ring-0 image of the x86 backend (the
// "bluepill" of SPEC section 3.2): the GDT, the IDT, the TSS template, and the
// machine code that SYSCALL and the exception gates run. The code spills the
// guest registers into the CommPage through GS, leaves the interrupt frame on
// the kernel stack, and executes HLT. The host reads the state, then runs
// the reload routine, which restores the registers and returns to user mode
// with IRETQ.
//
// The generator has no host dependency, so unit tests verify it on every OS.

// x86 segment selectors. The values match the Linux x86-64 layout, because the
// Sentry stores them in the user registers.
const (
	x86KernelCS uint64 = 0x10
	x86KernelSS uint64 = 0x18
	x86UserCS32 uint64 = 0x23
	x86UserSS   uint64 = 0x2b
	x86UserCS64 uint64 = 0x33
)

// Interrupt vectors and the SYSCALL marker.
const (
	x86VecDivide      = 0
	x86VecDebug       = 1
	x86VecBreakpoint  = 3
	x86VecOverflow    = 4
	x86VecBound       = 5
	x86VecInvalidOp   = 6
	x86VecDeviceNA    = 7
	x86VecDoubleFault = 8
	x86VecInvalidTSS  = 10
	x86VecSegNotPres  = 11
	x86VecStackFault  = 12
	x86VecGeneralProt = 13
	x86VecPageFault   = 14
	x86VecX87         = 16
	x86VecAlignment   = 17
	x86VecMachineChk  = 18
	x86VecSIMD        = 19
	// x86VecBounce is #VE. The host injects it to take a vCPU out of user mode.
	x86VecBounce = 20
	x86VecInt80  = 0x80
	// x86VecSyscall is above 255, so no hardware vector collides with it.
	x86VecSyscall = 0x100

	x86ExceptionVectors = 32
)

// vectorHasErrorCode reports whether the CPU pushes an error code for the
// exception vector.
func x86VectorHasErrorCode(vec int) bool {
	switch vec {
	case 8, 10, 11, 12, 13, 14, 17, 21, 29, 30:
		return true
	}
	return false
}

// Offsets of the routines inside the code page.
const (
	x86CodeSyscall   = 0x000
	x86CodeStubs     = 0x100 // 32 stubs of 16 bytes.
	x86CodeStubSize  = 16
	x86CodeInt80     = 0x300
	x86CodeCommon    = 0x400 // Starts with SWAPGS.
	x86CodeSpill     = x86CodeCommon + 3
	x86CodeReload    = 0x500
	x86CodePageBytes = 4096
)

// CommPage offsets used by the generated code.
const (
	x86OffRegs    = unsafe.Offsetof(x86CommPage{}.Regs)
	x86OffScratch = unsafe.Offsetof(x86CommPage{}.Scratch)
	x86OffStack   = unsafe.Offsetof(x86CommPage{}.Stack)
	x86OffCR2     = unsafe.Offsetof(x86CommPage{}.CR2)
	x86OffTSS     = unsafe.Offsetof(x86CommPage{}.TSS)
)

// x86CodeBuilder appends machine code to the code page.
type x86CodeBuilder struct {
	page []byte
	off  int
}

func (b *x86CodeBuilder) emit(bytes ...byte) {
	copy(b.page[b.off:], bytes)
	b.off += len(bytes)
}

func (b *x86CodeBuilder) emitLE32(v uint32) {
	binary.LittleEndian.PutUint32(b.page[b.off:], v)
	b.off += 4
}

// swapgs: 0F 01 F8.
func (b *x86CodeBuilder) swapgs() { b.emit(0x0f, 0x01, 0xf8) }

// hlt: F4.
func (b *x86CodeBuilder) hlt() { b.emit(0xf4) }

// iretq: 48 CF.
func (b *x86CodeBuilder) iretq() { b.emit(0x48, 0xcf) }

// rex returns the REX.W prefix with REX.R for registers 8 to 15.
func x86REX(reg int) byte {
	if reg >= 8 {
		return 0x4c
	}
	return 0x48
}

// movToGS stores a 64-bit register at GS:disp32. Encoding: 65 REX.W 89 /r with
// a SIB byte that selects absolute disp32 addressing.
func (b *x86CodeBuilder) movToGS(reg int, disp uintptr) {
	b.emit(0x65, x86REX(reg), 0x89, byte(reg&7)<<3|0x04, 0x25)
	b.emitLE32(uint32(disp))
}

// movFromGS loads a 64-bit register from GS:disp32: 65 REX.W 8B /r.
func (b *x86CodeBuilder) movFromGS(reg int, disp uintptr) {
	b.emit(0x65, x86REX(reg), 0x8b, byte(reg&7)<<3|0x04, 0x25)
	b.emitLE32(uint32(disp))
}

// pushGS pushes the 64-bit value at GS:disp32: 65 FF /6.
func (b *x86CodeBuilder) pushGS(disp uintptr) {
	b.emit(0x65, 0xff, 0x34, 0x25)
	b.emitLE32(uint32(disp))
}

// pushImm pushes a sign-extended immediate: 6A ib or 68 id.
func (b *x86CodeBuilder) pushImm(v int32) {
	if v >= -128 && v <= 127 {
		b.emit(0x6a, byte(v))
		return
	}
	b.emit(0x68)
	b.emitLE32(uint32(v))
}

// pushReg pushes a 64-bit register: 50+r, or 41 50+r for registers 8 to 15.
func (b *x86CodeBuilder) pushReg(reg int) {
	if reg >= 8 {
		b.emit(0x41, 0x50+byte(reg-8))
		return
	}
	b.emit(0x50 + byte(reg))
}

// jmp emits JMP rel32 to the page offset target.
func (b *x86CodeBuilder) jmp(target int) {
	b.emit(0xe9)
	b.emitLE32(uint32(int32(target - (b.off + 4))))
}

// Register numbers in hardware order.
const (
	x86RAX = 0
	x86RCX = 1
	x86RSP = 4
	x86R11 = 11
)

// x86KernelImage holds the generated pages.
type x86KernelImage struct {
	GDT  []byte // One 4KB page.
	IDT  []byte // One 4KB page.
	Code []byte // One 4KB page.
	// HLTOffset is the page offset of the HLT that ends the spill routine.
	HLTOffset int
}

// x86GDTEntries are the descriptors at the Linux-compatible indexes. Every
// accessed bit is set, so the CPU never writes the read-only GDT page.
var x86GDTEntries = [...]uint64{
	0, 0,
	0x00af9b000000ffff, // 0x10: kernel code, 64-bit, DPL 0.
	0x00cf93000000ffff, // 0x18: kernel data, DPL 0.
	0x00cffb000000ffff, // 0x20: user code, 32-bit compatibility, DPL 3 (selector 0x23).
	0x00cff3000000ffff, // 0x28: user data, DPL 3 (selector 0x2b).
	0x00affb000000ffff, // 0x30: user code, 64-bit, DPL 3 (selector 0x33).
}

// x86GDTLimit is the GDTR limit for the descriptor table.
const x86GDTLimit = len(x86GDTEntries)*8 - 1

// x86IDTLimit is the IDTR limit: 256 gates of 16 bytes.
const x86IDTLimit = 256*16 - 1

// x86TSSLimit is the TSS limit: the 104-byte structure without an I/O bitmap.
const x86TSSLimit = 103

// x86TSSRSP0Offset is the offset of RSP0 inside the TSS.
const x86TSSRSP0Offset = 4

// x86TSSIOMapOffset is the offset of the I/O map base inside the TSS.
const x86TSSIOMapOffset = 102

// x86FillTSS writes the TSS template into the TSS array of a CommPage. The I/O
// map base points past the limit, so user I/O instructions raise #GP.
func x86FillTSS(tss []byte, kernelStackTop uint64) {
	clear(tss)
	binary.LittleEndian.PutUint64(tss[x86TSSRSP0Offset:], kernelStackTop)
	binary.LittleEndian.PutUint16(tss[x86TSSIOMapOffset:], 104)
}

// x86IDTGate encodes a 64-bit interrupt gate at the kernel code segment. User
// code reaches the gate with an INT instruction only when dpl is 3.
func x86IDTGate(handler uint64, dpl int) [16]byte {
	var g [16]byte
	binary.LittleEndian.PutUint16(g[0:], uint16(handler))
	binary.LittleEndian.PutUint16(g[2:], uint16(x86KernelCS))
	g[4] = 0                     // IST 0: the TSS stack serves the gate.
	g[5] = 0x8e | byte(dpl&3)<<5 // Present, interrupt gate.
	binary.LittleEndian.PutUint16(g[6:], uint16(handler>>16))
	binary.LittleEndian.PutUint32(g[8:], uint32(handler>>32))
	return g
}

// buildX86Kernel generates the three kernel pages. codeVA is the virtual
// address where the code page will be mapped, because the IDT gates hold
// absolute handler addresses.
func buildX86Kernel(codeVA uint64) x86KernelImage {
	img := x86KernelImage{
		GDT:  make([]byte, 4096),
		IDT:  make([]byte, 4096),
		Code: make([]byte, x86CodePageBytes),
	}
	for i, e := range x86GDTEntries {
		binary.LittleEndian.PutUint64(img.GDT[i*8:], e)
	}

	b := &x86CodeBuilder{page: img.Code}

	// SYSCALL entry. The CPU leaves the user stack pointer in RSP, the return
	// address in RCX and the flags in R11. The code switches to the kernel
	// stack and builds the same frame that an exception from user mode gets.
	b.off = x86CodeSyscall
	b.swapgs()
	b.movToGS(x86RSP, x86OffScratch)
	b.movFromGS(x86RSP, x86OffStack)
	b.pushImm(int32(x86UserSS))
	b.pushGS(x86OffScratch)
	b.pushReg(x86R11)
	b.pushImm(int32(x86UserCS64))
	b.pushReg(x86RCX)
	b.pushImm(0) // Error code slot.
	b.pushImm(x86VecSyscall)
	b.jmp(x86CodeSpill)

	// One stub per exception vector: push a dummy error code when the CPU
	// pushes none, push the vector, and join the common code.
	for vec := range x86ExceptionVectors {
		b.off = x86CodeStubs + vec*x86CodeStubSize
		if !x86VectorHasErrorCode(vec) {
			b.pushImm(0)
		}
		b.pushImm(int32(vec))
		b.jmp(x86CodeCommon)
		if b.off > x86CodeStubs+(vec+1)*x86CodeStubSize {
			panic(fmt.Sprintf("hvf: stub for vector %d overflows its slot", vec))
		}
	}
	b.off = x86CodeInt80
	b.pushImm(0)
	b.pushImm(x86VecInt80)
	b.jmp(x86CodeCommon)

	// Common entry for exceptions from user mode: switch to the kernel GS
	// base, then spill every register except RSP.
	b.off = x86CodeCommon
	b.swapgs()
	if b.off != x86CodeSpill {
		panic("hvf: SWAPGS length changed")
	}
	for reg := range 16 {
		if reg != x86RSP {
			b.movToGS(reg, x86OffRegs+uintptr(8*reg))
		}
	}
	// CR2 into RAX: mov %cr2, %rax is 0F 20 D0. RAX is already spilled.
	b.emit(0x0f, 0x20, 0xd0)
	b.movToGS(x86RAX, x86OffCR2)
	img.HLTOffset = b.off
	b.hlt()
	b.emit(0xeb, 0xfd) // JMP back to HLT: the host never resumes here.
	if b.off > x86CodeReload {
		panic("hvf: the spill routine overruns the reload routine")
	}

	// Reload routine: the host sets RIP here and points RSP at the vector slot
	// of the frame. The code restores the registers, drops the vector and the
	// error code, then returns to user mode.
	b.off = x86CodeReload
	for reg := range 16 {
		if reg != x86RSP {
			b.movFromGS(reg, x86OffRegs+uintptr(8*reg))
		}
	}
	b.emit(0x48, 0x83, 0xc4, 0x10) // add $16, %rsp
	b.swapgs()
	b.iretq()

	// The IDT: gates for the exception vectors and INT 0x80. Every other vector
	// stays not present, so a stray INT n raises #GP.
	for vec := range x86ExceptionVectors {
		dpl := 0
		if vec == x86VecBreakpoint {
			dpl = 3
		}
		g := x86IDTGate(codeVA+uint64(x86CodeStubs+vec*x86CodeStubSize), dpl)
		copy(img.IDT[vec*16:], g[:])
	}
	g := x86IDTGate(codeVA+x86CodeInt80, 3)
	copy(img.IDT[x86VecInt80*16:], g[:])
	return img
}
