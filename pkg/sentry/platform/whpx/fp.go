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

// This file converts between the Sentry floating-point image and the
// register values of the Windows Hypervisor Platform. The converters are pure
// functions, so tests run them on every host.
//
// On amd64 the image is an FXSAVE area. The partition enables only the x87
// and SSE state components, because the WHPX register interface cannot read
// the upper halves of the YMM registers.
//
// On arm64 the image follows the layout of ring0.SaveFloatingPoint: FPSR at
// byte 0, FPCR at byte 8 and Q0 to Q31 from byte 16.

// FXSAVE area layout.
const (
	fxsaveSize     = 512
	fxOffFCW       = 0
	fxOffFSW       = 2
	fxOffFTW       = 4
	fxOffFOP       = 6
	fxOffFIP       = 8
	fxOffFDP       = 16
	fxOffMXCSR     = 24
	fxOffMXCSRMask = 28
	fxOffST        = 32
	fxOffXMM       = 160

	// x86XsaveHeaderOff is the offset of XSTATE_BV in an XSAVE area.
	x86XsaveHeaderOff = 512

	// x86XsaveLegacyBits are the x87 and SSE bits of XSTATE_BV.
	x86XsaveLegacyBits = 3

	// x86MXCSRMaskDefault is the MXCSR mask of CPUs that report zero.
	x86MXCSRMaskDefault = 0xFFBF

	// x86XmmStatusMask is the XmmStatusControlMask that QEMU writes.
	x86XmmStatusMask = 0x0000FFFF
)

// Bits of WHV_X64_FP_CONTROL_STATUS_REGISTER and the FXSAVE layout shared
// with it.
const (
	fpStatusTopShift = 11
	fpStatusTopMask  = 7
)

// x86FPRegCount is the number of registers in a legacy FP read or write: 16
// XMM registers, 8 x87 registers and 2 control registers.
const x86FPRegCount = 26

// x86WantFP appends the legacy floating-point registers to a read batch.
func x86WantFP(b *regBatch) {
	for i := range 16 {
		b.want(x64RegXmm0 + uint32(i))
	}
	for i := range 8 {
		b.want(x64RegFpMmx0 + uint32(i))
	}
	b.want(x64RegFpControlStatus)
	b.want(x64RegXmmControlStatus)
}

// x86FXSaveFromRegs writes the registers that x86WantFP requested into the
// FXSAVE area at the start of image. first is the batch index of the first
// FP register. The function leaves every byte above the FXSAVE area alone,
// except that it marks the x87 and SSE components valid in an XSAVE header.
func x86FXSaveFromRegs(image []byte, b *regBatch, first int) error {
	if len(image) < fxsaveSize {
		return fmt.Errorf("whpx: FP image is %d bytes, want at least %d", len(image), fxsaveSize)
	}
	fx := image[:fxsaveSize]
	for i := range 16 {
		lo, hi := b.u128(first + i)
		binary.LittleEndian.PutUint64(fx[fxOffXMM+i*16:], lo)
		binary.LittleEndian.PutUint64(fx[fxOffXMM+i*16+8:], hi)
	}
	ctlLo, ctlHi := b.u128(first + 24)
	fcw := uint16(ctlLo)
	fsw := uint16(ctlLo >> 16)
	ftw := uint8(ctlLo >> 32)
	fop := uint16(ctlLo >> 48)
	binary.LittleEndian.PutUint16(fx[fxOffFCW:], fcw)
	binary.LittleEndian.PutUint16(fx[fxOffFSW:], fsw)
	fx[fxOffFTW] = ftw
	fx[fxOffFTW+1] = 0
	binary.LittleEndian.PutUint16(fx[fxOffFOP:], fop)
	binary.LittleEndian.PutUint64(fx[fxOffFIP:], ctlHi)

	xmmLo, xmmHi := b.u128(first + 25)
	binary.LittleEndian.PutUint64(fx[fxOffFDP:], xmmLo)
	binary.LittleEndian.PutUint32(fx[fxOffMXCSR:], uint32(xmmHi))
	binary.LittleEndian.PutUint32(fx[fxOffMXCSRMask:], uint32(xmmHi>>32))

	// FpMmx0 to FpMmx7 name the physical x87 registers. FXSAVE stores them
	// in stack order, ST(i) being physical register (TOP + i) mod 8.
	top := int(fsw>>fpStatusTopShift) & fpStatusTopMask
	for i := range 8 {
		lo, hi := b.u128(first + 16 + (top+i)&7)
		slot := fx[fxOffST+i*16 : fxOffST+(i+1)*16]
		binary.LittleEndian.PutUint64(slot[0:], lo)
		binary.LittleEndian.PutUint16(slot[8:], uint16(hi))
		clear(slot[10:])
	}
	if len(image) >= x86XsaveHeaderOff+8 {
		bv := binary.LittleEndian.Uint64(image[x86XsaveHeaderOff:])
		binary.LittleEndian.PutUint64(image[x86XsaveHeaderOff:], bv|x86XsaveLegacyBits)
	}
	return nil
}

// x86FXSaveToRegs appends the register writes that load the FXSAVE area at
// the start of image into a virtual processor.
func x86FXSaveToRegs(b *regBatch, image []byte) error {
	if len(image) < fxsaveSize {
		return fmt.Errorf("whpx: FP image is %d bytes, want at least %d", len(image), fxsaveSize)
	}
	fx := image[:fxsaveSize]
	for i := range 16 {
		b.add128(x64RegXmm0+uint32(i),
			binary.LittleEndian.Uint64(fx[fxOffXMM+i*16:]),
			binary.LittleEndian.Uint64(fx[fxOffXMM+i*16+8:]))
	}
	fsw := binary.LittleEndian.Uint16(fx[fxOffFSW:])
	top := int(fsw>>fpStatusTopShift) & fpStatusTopMask
	var phys [8][2]uint64
	for i := range 8 {
		slot := fx[fxOffST+i*16 : fxOffST+(i+1)*16]
		phys[(top+i)&7] = [2]uint64{
			binary.LittleEndian.Uint64(slot[0:]),
			uint64(binary.LittleEndian.Uint16(slot[8:])),
		}
	}
	for i := range 8 {
		b.add128(x64RegFpMmx0+uint32(i), phys[i][0], phys[i][1])
	}
	lo := uint64(binary.LittleEndian.Uint16(fx[fxOffFCW:])) |
		uint64(fsw)<<16 |
		uint64(fx[fxOffFTW])<<32 |
		uint64(binary.LittleEndian.Uint16(fx[fxOffFOP:]))<<48
	b.add128(x64RegFpControlStatus, lo, binary.LittleEndian.Uint64(fx[fxOffFIP:]))

	mask := binary.LittleEndian.Uint32(fx[fxOffMXCSRMask:])
	if mask == 0 {
		mask = x86MXCSRMaskDefault
	}
	mxcsr := binary.LittleEndian.Uint32(fx[fxOffMXCSR:]) & mask
	b.add128(x64RegXmmControlStatus,
		binary.LittleEndian.Uint64(fx[fxOffFDP:]),
		uint64(mxcsr)|uint64(x86XmmStatusMask)<<32)
	return nil
}

// Layout of the arm64 floating-point image.
const (
	a64FPOffFPSR = 0
	a64FPOffFPCR = 8
	a64FPOffQ    = 16
	a64FPSize    = 528

	// a64FPRegCount is the number of registers in an FP read or write: Q0 to
	// Q31, FPCR and FPSR.
	a64FPRegCount = 34
)

// a64WantFP appends the vector registers and the FP control registers to a
// read batch.
func a64WantFP(b *regBatch) {
	for i := range 32 {
		b.want(a64RegQ0 + uint32(i))
	}
	b.want(a64RegFpcr)
	b.want(a64RegFpsr)
}

// a64FPFromRegs writes the registers that a64WantFP requested into image.
func a64FPFromRegs(image []byte, b *regBatch, first int) error {
	if len(image) < a64FPSize {
		return fmt.Errorf("whpx: FP image is %d bytes, want at least %d", len(image), a64FPSize)
	}
	for i := range 32 {
		lo, hi := b.u128(first + i)
		binary.LittleEndian.PutUint64(image[a64FPOffQ+i*16:], lo)
		binary.LittleEndian.PutUint64(image[a64FPOffQ+i*16+8:], hi)
	}
	binary.LittleEndian.PutUint64(image[a64FPOffFPCR:], b.u64(first+32))
	binary.LittleEndian.PutUint64(image[a64FPOffFPSR:], b.u64(first+33))
	return nil
}

// a64FPToRegs appends the register writes that load image into a virtual
// processor.
func a64FPToRegs(b *regBatch, image []byte) error {
	if len(image) < a64FPSize {
		return fmt.Errorf("whpx: FP image is %d bytes, want at least %d", len(image), a64FPSize)
	}
	for i := range 32 {
		b.add128(a64RegQ0+uint32(i),
			binary.LittleEndian.Uint64(image[a64FPOffQ+i*16:]),
			binary.LittleEndian.Uint64(image[a64FPOffQ+i*16+8:]))
	}
	b.add64(a64RegFpcr, binary.LittleEndian.Uint64(image[a64FPOffFPCR:]))
	b.add64(a64RegFpsr, binary.LittleEndian.Uint64(image[a64FPOffFPSR:]))
	return nil
}
