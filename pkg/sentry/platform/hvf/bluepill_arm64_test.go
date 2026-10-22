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
	"testing"
	"unsafe"
)

func word(page []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(page[off : off+4])
}

// The encoders must reproduce words that ran on real hardware in the earlier
// hand-written stub. The constants below come from that stub.
func TestEncodersMatchKnownGoodWords(t *testing.T) {
	cases := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"STP X0,X1,[SP]", encPairX(false, 0, 1, 0), 0xa90007e0},
		{"LDP X0,X1,[SP,#248]", encPairX(true, 0, 1, 248), 0xa9400000 | 31<<15 | 1<<10 | 31<<5},
		{"STP X2,X3,[SP,#264]", encPairX(false, 2, 3, 264), 0xa9000000 | 33<<15 | 3<<10 | 31<<5 | 2},
		{"STR X30,[SP,#240]", encSTRX(30, 240), 0xf9000000 | 30<<10 | 31<<5 | 30},
		{"LDR X0,[SP,#832]", encLDRX(0, 832), 0xf9400000 | 104<<10 | 31<<5},
		{"STP Q0,Q1,[SP,#320]", encPairQ(false, 0, 1, 320), 0xad000000 | 20<<15 | 1<<10 | 31<<5},
		{"LDP Q30,Q31,[SP,#800]", encPairQ(true, 30, 31, 800), 0xad400000 | 50<<15 | 31<<10 | 31<<5 | 30},
		{"MRS X0,SP_EL0", encMRS(sysRegSPEL0, 0), 0xd5384100},
		{"MRS X1,ELR_EL1", encMRS(sysRegELREL1, 1), 0xd5384021},
		{"MRS X2,SPSR_EL1", encMRS(sysRegSPSREL1, 2), 0xd5384002},
		{"MRS X3,TPIDR_EL0", encMRS(sysRegTPIDREL0, 3), 0xd53bd043},
		{"MRS X4,FAR_EL1", encMRS(sysRegFAREL1, 4), 0xd5386004},
		{"MRS X5,ESR_EL1", encMRS(sysRegESREL1, 5), 0xd5385205},
		{"MRS X0,FPSR", encMRS(sysRegFPSR, 0), 0xd53b4420},
		{"MRS X1,FPCR", encMRS(sysRegFPCR, 1), 0xd53b4401},
		{"MSR SP_EL0,X0", encMSR(sysRegSPEL0, 0), 0xd5184100},
		{"MSR ELR_EL1,X1", encMSR(sysRegELREL1, 1), 0xd5184021},
		{"MSR SPSR_EL1,X2", encMSR(sysRegSPSREL1, 2), 0xd5184002},
		{"MSR TPIDR_EL0,X3", encMSR(sysRegTPIDREL0, 3), 0xd51bd043},
		{"MSR FPSR,X0", encMSR(sysRegFPSR, 0), 0xd51b4420},
		{"MSR FPCR,X1", encMSR(sysRegFPCR, 1), 0xd51b4401},
		{"MOVZ X0,#7", encMOVZ(0, 7), 0xd2800000 | 7<<5},
		{"B +0x7f4", encB(0x7f4), 0x14000000 | 0x7f4/4},
		{"B -8", encB(-8), 0x17fffffe},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %#08x, want %#08x", tc.name, tc.got, tc.want)
		}
	}
}

func TestVectorPageLayout(t *testing.T) {
	page := buildVectorPage()
	if len(page) != 4096 {
		t.Fatalf("vector page has %d bytes, want 4096", len(page))
	}
	if got := word(page, vectorReloadOffset-4); got != insnHVC0 {
		t.Errorf("word before the reload routine = %#08x, want HVC #0 (%#08x)", got, insnHVC0)
	}
	// Every slot records its own index in X0 and jumps to the common routine.
	for slot := range vectorSlotCount {
		base := slot * vectorSlotSize
		if got, want := word(page, base), encPairX(false, 0, 1, 0); got != want {
			t.Errorf("slot %d first word = %#08x, want STP X0,X1", slot, got)
		}
		if got, want := word(page, base+4), encMOVZ(0, uint32(slot)); got != want {
			t.Errorf("slot %d second word = %#08x, want MOVZ X0,#%d", slot, got, slot)
		}
		branch := word(page, base+12)
		if branch>>26 != 0x14000000>>26 {
			t.Fatalf("slot %d fourth word %#08x is not a branch", slot, branch)
		}
		target := base + 12 + int(int32(branch<<6)>>6)*4
		if target != vectorCommonOffset {
			t.Errorf("slot %d branches to %#x, want %#x", slot, target, vectorCommonOffset)
		}
	}
	// ERET appears once, as the last instruction of the reload routine.
	eret := -1
	for off := vectorReloadOffset; off+4 <= len(page); off += 4 {
		if word(page, off) == insnERET {
			if eret != -1 {
				t.Fatalf("second ERET at %#x", off)
			}
			eret = off
		}
	}
	if eret < 0 {
		t.Fatal("no ERET in the reload routine")
	}
	for off := eret + 4; off < len(page); off += 4 {
		if word(page, off) != 0 {
			t.Fatalf("non-zero word %#08x after ERET at %#x", word(page, off), off)
		}
	}
}

// The first reload instruction loads the flush flags, and the branches skip
// exactly the flush blocks that the flags do not select.
func TestReloadRoutineFlushBranches(t *testing.T) {
	page := buildVectorPage()
	at := vectorReloadOffset
	if got, want := word(page, at), encLDRX(0, commOffFlags); got != want {
		t.Fatalf("first reload word = %#08x, want LDR X0,[SP,Flags]", got)
	}
	cbz := word(page, at+4)
	if cbz&0xff000000 != 0xb4000000 {
		t.Fatalf("second reload word %#08x is not CBZ", cbz)
	}
	cbzTarget := at + 4 + int(int32(cbz<<8)>>13)*4
	if got := word(page, cbzTarget); got != encLDRX(0, commOffFPSR) {
		t.Errorf("CBZ target holds %#08x, want the first FPSR reload word", got)
	}
	tbzTLB, tlbi := word(page, at+8), word(page, at+12)
	if tlbi != insnTLBIVMALLE1 {
		t.Errorf("word after the first TBZ = %#08x, want TLBI VMALLE1", tlbi)
	}
	tbzIC, ic := word(page, at+16), word(page, at+20)
	if ic != insnICIALLUIS {
		t.Errorf("word after the second TBZ = %#08x, want IC IALLUIS", ic)
	}
	bitOf := func(insn uint32) uint32 { return insn >> 19 & 0x1f }
	if bitOf(tbzTLB) != 0 || bitOf(tbzIC) != 1 {
		t.Errorf("TBZ tests bits %d and %d, want 0 and 1", bitOf(tbzTLB), bitOf(tbzIC))
	}
	if flagFlushTLB != 1<<0 || flagFlushICache != 1<<1 {
		t.Errorf("flush flag values changed: TLB=%#x IC=%#x", flagFlushTLB, flagFlushICache)
	}
}

func TestCommPageLayoutMatchesStub(t *testing.T) {
	var c CommPage
	if got := unsafe.Sizeof(c); got != 4096 {
		t.Fatalf("CommPage size = %d, want 4096", got)
	}
	// The stub stores register pairs, so these fields must stay adjacent and in order.
	pairs := []struct {
		name         string
		first, next  uintptr
		wantDistance uintptr
	}{
		{"SP,PC", unsafe.Offsetof(c.SP), unsafe.Offsetof(c.PC), 8},
		{"Pstate,TLS", unsafe.Offsetof(c.Pstate), unsafe.Offsetof(c.TLS), 8},
		{"FaultAddr,ESR", unsafe.Offsetof(c.FaultAddr), unsafe.Offsetof(c.ESR), 8},
		{"FPSR,FPCR", unsafe.Offsetof(c.FPSR), unsafe.Offsetof(c.FPCR), 8},
	}
	for _, p := range pairs {
		if p.next-p.first != p.wantDistance {
			t.Errorf("%s are %d bytes apart, want %d", p.name, p.next-p.first, p.wantDistance)
		}
	}
	if got := unsafe.Offsetof(c.Pstate); got != unsafe.Offsetof(c.PC)+8 {
		t.Errorf("Pstate offset %d does not follow PC", got)
	}
	if off := unsafe.Offsetof(c.VRegs); off%16 != 0 {
		t.Errorf("VRegs offset %d is not 16-byte aligned for STP Q", off)
	}
	if off := unsafe.Offsetof(c.Regs); off != 0 {
		t.Errorf("Regs offset = %d, want 0", off)
	}
}

func TestTCRValue(t *testing.T) {
	tcr := tcrEL1(1)
	field := func(shift, width uint) uint64 { return tcr >> shift & (1<<width - 1) }
	checks := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"T0SZ", field(0, 6), 16},
		{"EPD0", field(7, 1), 0},
		{"TG0", field(14, 2), 0},
		{"T1SZ", field(16, 6), 16},
		{"EPD1", field(23, 1), 0},
		{"TG1", field(30, 2), 2},
		{"IPS", field(32, 3), 1},
		{"TBI0", field(37, 1), 1},
		{"TBI1", field(38, 1), 0},
		{"SH0", field(12, 2), 3},
		{"SH1", field(28, 2), 3},
		{"IRGN1", field(24, 2), 1},
		{"ORGN1", field(26, 2), 1},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("TCR_EL1.%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}
