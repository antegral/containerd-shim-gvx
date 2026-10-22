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
	"bytes"
	"encoding/binary"
	"testing"
)

func fxsampleImage() []byte {
	img := make([]byte, 576)
	for i := range 16 {
		binary.LittleEndian.PutUint64(img[fxOffXMM+i*16:], 0x1111_0000_0000_0000|uint64(i))
		binary.LittleEndian.PutUint64(img[fxOffXMM+i*16+8:], 0x2222_0000_0000_0000|uint64(i))
	}
	binary.LittleEndian.PutUint16(img[fxOffFCW:], 0x037F)
	// TOP is 3, so ST(0) is physical register 3.
	binary.LittleEndian.PutUint16(img[fxOffFSW:], 3<<11|0x20)
	img[fxOffFTW] = 0b0001_0110
	binary.LittleEndian.PutUint16(img[fxOffFOP:], 0x07D9)
	binary.LittleEndian.PutUint64(img[fxOffFIP:], 0x0000_7FFF_1234_5678)
	binary.LittleEndian.PutUint64(img[fxOffFDP:], 0x0000_7FFF_8765_4321)
	binary.LittleEndian.PutUint32(img[fxOffMXCSR:], 0x1F80)
	binary.LittleEndian.PutUint32(img[fxOffMXCSRMask:], 0xFFFF)
	for i := range 8 {
		binary.LittleEndian.PutUint64(img[fxOffST+i*16:], 0xAAAA_0000_0000_0000|uint64(i))
		binary.LittleEndian.PutUint16(img[fxOffST+i*16+8:], 0x4000|uint16(i))
	}
	return img
}

func TestX86FXSaveToRegistersLayout(t *testing.T) {
	img := fxsampleImage()
	b := newRegBatch(x86FPRegCount)
	if err := x86FXSaveToRegs(b, img); err != nil {
		t.Fatal(err)
	}
	if b.n != x86FPRegCount {
		t.Fatalf("batch has %d registers, want %d", b.n, x86FPRegCount)
	}
	names, _ := b.view()
	for i := range 16 {
		if names[i] != x64RegXmm0+uint32(i) {
			t.Errorf("register %d is %#x, want Xmm%d", i, names[i], i)
		}
		lo, hi := b.u128(i)
		if lo != 0x1111_0000_0000_0000|uint64(i) || hi != 0x2222_0000_0000_0000|uint64(i) {
			t.Errorf("Xmm%d is %#x:%#x", i, hi, lo)
		}
	}
	// FXSAVE stores ST(i) in stack order. FpMmx registers are physical, so
	// with TOP=3 the register FpMmx3 holds ST(0) and FpMmx2 holds ST(7).
	for phys := range 8 {
		st := (phys - 3) & 7
		lo, hi := b.u128(16 + phys)
		if names[16+phys] != x64RegFpMmx0+uint32(phys) {
			t.Errorf("register %d is %#x, want FpMmx%d", 16+phys, names[16+phys], phys)
		}
		if lo != 0xAAAA_0000_0000_0000|uint64(st) || hi != 0x4000|uint64(st) {
			t.Errorf("FpMmx%d holds ST(%d) as %#x:%#x, want mantissa and exponent of ST(%d)", phys, st, lo, hi, st)
		}
	}
	if names[24] != x64RegFpControlStatus || names[25] != x64RegXmmControlStatus {
		t.Fatalf("control registers are %#x and %#x", names[24], names[25])
	}
	lo, hi := b.u128(24)
	if uint16(lo) != 0x037F || uint16(lo>>16) != 3<<11|0x20 || uint8(lo>>32) != 0b0001_0110 || uint16(lo>>48) != 0x07D9 {
		t.Errorf("FpControlStatus low word is %#x", lo)
	}
	if hi != 0x0000_7FFF_1234_5678 {
		t.Errorf("LastFpRip is %#x", hi)
	}
	lo, hi = b.u128(25)
	if lo != 0x0000_7FFF_8765_4321 || uint32(hi) != 0x1F80 || uint32(hi>>32) != x86XmmStatusMask {
		t.Errorf("XmmControlStatus is %#x:%#x", hi, lo)
	}
}

func TestX86FXSaveRoundTrip(t *testing.T) {
	img := fxsampleImage()
	b := newRegBatch(x86FPRegCount)
	if err := x86FXSaveToRegs(b, img); err != nil {
		t.Fatal(err)
	}
	// Reading back the same registers must rebuild the image. The upper
	// bytes of each ST slot are reserved and stay zero.
	back := make([]byte, 576)
	if err := x86FXSaveFromRegs(back, b, 0); err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(img)
	for i := range 8 {
		clear(want[fxOffST+i*16+10 : fxOffST+(i+1)*16])
	}
	binary.LittleEndian.PutUint64(want[x86XsaveHeaderOff:], x86XsaveLegacyBits)
	// The hypervisor mask replaces the image mask.
	binary.LittleEndian.PutUint32(want[fxOffMXCSRMask:], x86XmmStatusMask)
	if !bytes.Equal(back[:fxsaveSize], want[:fxsaveSize]) {
		for i := range fxsaveSize {
			if back[i] != want[i] {
				t.Fatalf("FXSAVE byte %#x is %#x, want %#x", i, back[i], want[i])
			}
		}
	}
	if got := binary.LittleEndian.Uint64(back[x86XsaveHeaderOff:]); got != x86XsaveLegacyBits {
		t.Errorf("XSTATE_BV is %#x, want %#x", got, x86XsaveLegacyBits)
	}
}

func TestX86FXSaveFromRegistersKeepsOtherXsaveComponents(t *testing.T) {
	// Extended components and the rest of the XSAVE header belong to the
	// Sentry. The converter only sets the x87 and SSE bits of XSTATE_BV.
	img := make([]byte, 1024)
	for i := fxsaveSize; i < len(img); i++ {
		img[i] = 0xEE
	}
	binary.LittleEndian.PutUint64(img[x86XsaveHeaderOff:], 0x4)
	b := newRegBatch(x86FPRegCount)
	if err := x86FXSaveToRegs(b, fxsampleImage()); err != nil {
		t.Fatal(err)
	}
	if err := x86FXSaveFromRegs(img, b, 0); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(img[x86XsaveHeaderOff:]); got != 0x4|x86XsaveLegacyBits {
		t.Errorf("XSTATE_BV is %#x, want %#x", got, 0x4|x86XsaveLegacyBits)
	}
	for i := x86XsaveHeaderOff + 8; i < len(img); i++ {
		if img[i] != 0xEE {
			t.Fatalf("byte %#x above XSTATE_BV changed to %#x", i, img[i])
		}
	}
}

func TestX86FXSaveMXCSRIsMasked(t *testing.T) {
	img := fxsampleImage()
	binary.LittleEndian.PutUint32(img[fxOffMXCSR:], 0xFFFF_FFFF)
	binary.LittleEndian.PutUint32(img[fxOffMXCSRMask:], 0)
	b := newRegBatch(x86FPRegCount)
	if err := x86FXSaveToRegs(b, img); err != nil {
		t.Fatal(err)
	}
	_, hi := b.u128(25)
	if got := uint32(hi); got != x86MXCSRMaskDefault {
		t.Errorf("MXCSR is %#x, want the reserved bits cleared with the default mask %#x", got, x86MXCSRMaskDefault)
	}
	img2 := fxsampleImage()
	binary.LittleEndian.PutUint32(img2[fxOffMXCSR:], 0xFFFF_FFFF)
	binary.LittleEndian.PutUint32(img2[fxOffMXCSRMask:], 0x0000_FFBF)
	b.reset()
	if err := x86FXSaveToRegs(b, img2); err != nil {
		t.Fatal(err)
	}
	if _, hi = b.u128(25); uint32(hi) != 0xFFBF {
		t.Errorf("MXCSR is %#x, want 0xffbf", uint32(hi))
	}
}

func TestX86WantFPNamesAndShortImages(t *testing.T) {
	b := newRegBatch(x86FPRegCount)
	x86WantFP(b)
	names, _ := b.view()
	if len(names) != x86FPRegCount || names[0] != x64RegXmm0 || names[15] != x64RegXmm0+15 ||
		names[16] != x64RegFpMmx0 || names[23] != x64RegFpMmx0+7 || names[24] != x64RegFpControlStatus || names[25] != x64RegXmmControlStatus {
		t.Errorf("read list is %#x", names)
	}
	if err := x86FXSaveToRegs(newRegBatch(x86FPRegCount), make([]byte, fxsaveSize-1)); err == nil {
		t.Error("short image accepted for a write")
	}
	if err := x86FXSaveFromRegs(make([]byte, fxsaveSize-1), b, 0); err == nil {
		t.Error("short image accepted for a read")
	}
}

func TestA64FPLayoutAndRoundTrip(t *testing.T) {
	img := make([]byte, a64FPSize)
	binary.LittleEndian.PutUint64(img[a64FPOffFPSR:], 0x0800_0010)
	binary.LittleEndian.PutUint64(img[a64FPOffFPCR:], 0x0040_0000)
	for i := range 32 {
		binary.LittleEndian.PutUint64(img[a64FPOffQ+i*16:], 0xAB00_0000_0000_0000|uint64(i))
		binary.LittleEndian.PutUint64(img[a64FPOffQ+i*16+8:], 0xCD00_0000_0000_0000|uint64(i))
	}
	b := newRegBatch(a64FPRegCount)
	if err := a64FPToRegs(b, img); err != nil {
		t.Fatal(err)
	}
	names, _ := b.view()
	if len(names) != a64FPRegCount {
		t.Fatalf("batch has %d registers, want %d", len(names), a64FPRegCount)
	}
	for i := range 32 {
		if names[i] != a64RegQ0+uint32(i) {
			t.Errorf("register %d is %#x, want Q%d", i, names[i], i)
		}
		if lo, hi := b.u128(i); lo != 0xAB00_0000_0000_0000|uint64(i) || hi != 0xCD00_0000_0000_0000|uint64(i) {
			t.Errorf("Q%d is %#x:%#x", i, hi, lo)
		}
	}
	if names[32] != a64RegFpcr || names[33] != a64RegFpsr || b.u64(32) != 0x0040_0000 || b.u64(33) != 0x0800_0010 {
		t.Errorf("FPCR and FPSR are %#x=%#x and %#x=%#x", names[32], b.u64(32), names[33], b.u64(33))
	}
	back := make([]byte, a64FPSize)
	if err := a64FPFromRegs(back, b, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, img) {
		t.Error("round trip changed the image")
	}

	wb := newRegBatch(a64FPRegCount)
	a64WantFP(wb)
	wn, _ := wb.view()
	if len(wn) != a64FPRegCount || wn[0] != a64RegQ0 || wn[31] != a64RegQ0+31 || wn[32] != a64RegFpcr || wn[33] != a64RegFpsr {
		t.Errorf("read list is %#x", wn)
	}
	if err := a64FPToRegs(newRegBatch(a64FPRegCount), make([]byte, a64FPSize-1)); err == nil {
		t.Error("short image accepted for a write")
	}
}
