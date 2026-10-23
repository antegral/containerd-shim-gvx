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

	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

func word(page []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(page[off : off+4])
}

func TestVectorPageLayout(t *testing.T) {
	page := buildVectorPage()
	if len(page) != 4096 {
		t.Fatalf("vector page has %d bytes, want 4096", len(page))
	}
	if got := word(page, vectorReloadOffset-4); got != hvcommon.HVC(0) {
		t.Errorf("word before the reload routine = %#08x, want HVC #0 (%#08x)", got, hvcommon.HVC(0))
	}
	// Every slot records its own index in X0 and jumps to the common routine.
	for slot := range vectorSlotCount {
		base := slot * vectorSlotSize
		if got, want := word(page, base), hvcommon.STPXSP(0, 1, 0); got != want {
			t.Errorf("slot %d first word = %#08x, want STP X0,X1", slot, got)
		}
		if got, want := word(page, base+4), hvcommon.MOVZ(0, uint16(slot)); got != want {
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
		if word(page, off) == hvcommon.ERET {
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
	if got, want := word(page, at), hvcommon.LDRXSP(0, int(commOffFlags)); got != want {
		t.Fatalf("first reload word = %#08x, want LDR X0,[SP,Flags]", got)
	}
	cbz := word(page, at+4)
	if cbz&0xff000000 != 0xb4000000 {
		t.Fatalf("second reload word %#08x is not CBZ", cbz)
	}
	cbzTarget := at + 4 + int(int32(cbz<<8)>>13)*4
	if got := word(page, cbzTarget); got != hvcommon.LDRXSP(0, int(commOffFPSR)) {
		t.Errorf("CBZ target holds %#08x, want the first FPSR reload word", got)
	}
	tbzTLB, tlbi := word(page, at+8), word(page, at+12)
	if tlbi != hvcommon.TLBIVMALLE1 {
		t.Errorf("word after the first TBZ = %#08x, want TLBI VMALLE1", tlbi)
	}
	tbzIC, ic := word(page, at+16), word(page, at+20)
	if ic != hvcommon.ICIALLUIS {
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
