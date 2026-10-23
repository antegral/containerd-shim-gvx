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

package hvcommon

import (
	"encoding/binary"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func decodeX86(t *testing.T, code []byte) string {
	t.Helper()
	inst, err := x86asm.Decode(code, 64)
	if err != nil {
		t.Fatalf("% x does not decode: %v", code, err)
	}
	if inst.Len != len(code) {
		t.Fatalf("% x holds %d bytes, the instruction has %d", code, len(code), inst.Len)
	}
	return x86asm.IntelSyntax(inst, 0, nil)
}

func TestX86AppendersDecodeAsIntended(t *testing.T) {
	for _, c := range []struct {
		name string
		code []byte
		want string
	}{
		{"swapgs", AppendSwapgs(nil), "swapgs"},
		{"hlt", AppendHlt(nil), "hlt"},
		{"iretq", AppendIretq(nil), "iretq"},
		{"store rax", AppendMovToGS(nil, 0, 0x108), "mov qword ptr gs:[0x108], rax"},
		{"store r9", AppendMovToGS(nil, 9, 0x40), "mov qword ptr gs:[0x40], r9"},
		{"store r15", AppendMovToGS(nil, 15, 0x7F8), "mov qword ptr gs:[0x7f8], r15"},
		{"load rsp", AppendMovFromGS(nil, 4, 0x20), "mov rsp, qword ptr gs:[0x20]"},
		{"load r11", AppendMovFromGS(nil, 11, 0x58), "mov r11, qword ptr gs:[0x58]"},
		{"push", AppendPushGS(nil, 0x110), "push qword ptr gs:[0x110]"},
		{"operand for an immediate store", append(append([]byte{0x65, 0xC7}, AppendGSOperand(nil, 0, 0x30)...), 1, 0, 0, 0), "mov dword ptr gs:[0x30], 0x1"},
	} {
		if got := decodeX86(t, c.code); got != c.want {
			t.Errorf("%s: % x decodes as %q, want %q", c.name, c.code, got, c.want)
		}
	}
}

func TestX86AppendersKeepWhatIsInFrontOfThem(t *testing.T) {
	prefix := []byte{0x90, 0x90}
	got := AppendMovToGS(append([]byte(nil), prefix...), 3, 8)
	if got[0] != 0x90 || got[1] != 0x90 || len(got) <= len(prefix) {
		t.Fatalf("the appender changed the bytes in front: % x", got)
	}
}

func TestVectorHasErrorCodeFollowsTheArchitecture(t *testing.T) {
	// Intel SDM volume 3, table 6-1: #DF, #TS, #NP, #SS, #GP, #PF, #AC, #CP,
	// and the two VMM and security exceptions at 29 and 30.
	want := map[int]bool{8: true, 10: true, 11: true, 12: true, 13: true, 14: true, 17: true, 21: true, 29: true, 30: true}
	for v := range 256 {
		if got := VectorHasErrorCode(v); got != want[v] {
			t.Errorf("VectorHasErrorCode(%d) = %v, want %v", v, got, want[v])
		}
	}
}

// descriptor splits a GDT descriptor into the fields that the tests check.
type descriptor struct {
	present, code, long, db, system bool
	dpl                             int
	limit                           uint32
	base                            uint32
	accessed                        bool
}

func parseDescriptor(d uint64) descriptor {
	access := byte(d >> 40)
	flags := byte(d >> 52)
	return descriptor{
		present:  access&0x80 != 0,
		dpl:      int(access >> 5 & 3),
		system:   access&0x10 == 0,
		code:     access&0x08 != 0,
		accessed: access&0x01 != 0,
		long:     flags&0x2 != 0,
		db:       flags&0x4 != 0,
		limit:    uint32(d&0xFFFF) | uint32(d>>48&0xF)<<16,
		base:     uint32(d>>16&0xFFFFFF) | uint32(d>>56)<<24,
	}
}

func TestGDTDescriptorsMatchTheirSelectors(t *testing.T) {
	for _, c := range []struct {
		name     string
		selector uint16
		desc     uint64
		code     bool
		long     bool
		db       bool
	}{
		{"kernel code", SelKernelCS, DescKernelCode64, true, true, false},
		{"kernel data", SelKernelSS, DescKernelData, false, false, true},
		{"user code 32", SelUserCS32, DescUserCode32, true, false, true},
		{"user data", SelUserSS, DescUserData, false, false, true},
		{"user code 64", SelUserCS64, DescUserCode64, true, true, false},
	} {
		d := parseDescriptor(c.desc)
		if !d.present || d.system || d.code != c.code || d.long != c.long || d.db != c.db {
			t.Errorf("%s: descriptor %#x decodes as %+v", c.name, c.desc, d)
		}
		if want := int(c.selector & 3); d.dpl != want {
			t.Errorf("%s: DPL %d does not match the RPL %d of selector %#x", c.name, d.dpl, want, c.selector)
		}
		if !d.accessed {
			t.Errorf("%s: the accessed bit is clear, so the CPU would write the read-only GDT page", c.name)
		}
		if d.base != 0 || d.limit != 0xFFFFF {
			t.Errorf("%s: base %#x limit %#x, want a flat segment", c.name, d.base, d.limit)
		}
	}
}

func TestSelectorsFollowTheLinuxLayoutAndSYSRET(t *testing.T) {
	if SelUserCS64 != 0x33 || SelUserSS != 0x2B || SelUserCS32 != 0x23 || SelKernelCS != 0x10 || SelKernelSS != 0x18 {
		t.Fatal("a selector differs from the Linux x86-64 layout that pkg/sentry/arch stores in user registers")
	}
	// SYSRET loads SS from STAR[63:48]+8 and the 64-bit CS from +16.
	if SelUserCS32+8 != SelUserSS || SelUserCS32+16 != SelUserCS64 {
		t.Errorf("the user selectors %#x, %#x, %#x do not follow the SYSRET layout", SelUserCS32, SelUserSS, SelUserCS64)
	}
	// SYSCALL loads SS from STAR[47:32]+8.
	if SelKernelCS+8 != SelKernelSS {
		t.Errorf("the kernel selectors %#x, %#x do not follow the SYSCALL layout", SelKernelCS, SelKernelSS)
	}
}

func TestFillTSS(t *testing.T) {
	tss := make([]byte, TSSSize+8)
	for i := range tss {
		tss[i] = 0xEE
	}
	FillTSS(tss, 0x7000_0000_1000)
	if got := binary.LittleEndian.Uint64(tss[TSSRSP0Offset:]); got != 0x7000_0000_1000 {
		t.Errorf("RSP0 = %#x", got)
	}
	// The base lies at the end of the structure, so the I/O bitmap is empty
	// and every user I/O instruction raises #GP.
	if got := binary.LittleEndian.Uint16(tss[TSSIOMapOffset:]); got != TSSSize {
		t.Errorf("I/O map base = %d, want %d", got, TSSSize)
	}
	for i, b := range tss[:TSSSize] {
		inRSP0 := i >= TSSRSP0Offset && i < TSSRSP0Offset+8
		inBase := i >= TSSIOMapOffset && i < TSSIOMapOffset+2
		if !inRSP0 && !inBase && b != 0 {
			t.Fatalf("byte %d of the TSS = %#x, want zero", i, b)
		}
	}
	for i := TSSSize; i < len(tss); i++ {
		if tss[i] != 0xEE {
			t.Fatalf("FillTSS wrote byte %d behind the structure", i)
		}
	}
	if TSSLimit != 103 || TSSIOMapOffset+2 != TSSSize {
		t.Errorf("TSS limit %d and I/O map base offset %d do not fit the 104-byte structure", TSSLimit, TSSIOMapOffset)
	}
}

func TestIDTGateEncodesAnInterruptGateAtTheKernelCodeSegment(t *testing.T) {
	const handler = 0xFFFF_8000_1234_5678
	for _, dpl := range []int{0, 3} {
		g := IDTGate(handler, dpl)
		lo := uint64(binary.LittleEndian.Uint16(g[0:])) | uint64(binary.LittleEndian.Uint16(g[6:]))<<16 | uint64(binary.LittleEndian.Uint32(g[8:]))<<32
		if lo != handler {
			t.Errorf("dpl %d: the gate names handler %#x, want %#x", dpl, lo, uint64(handler))
		}
		if sel := binary.LittleEndian.Uint16(g[2:]); sel != SelKernelCS {
			t.Errorf("dpl %d: selector %#x, want the kernel code segment %#x", dpl, sel, SelKernelCS)
		}
		if g[4] != 0 {
			t.Errorf("dpl %d: IST = %d, want 0 so the TSS stack serves the gate", dpl, g[4])
		}
		if typ := g[5] & 0x1F; typ != 0xE {
			t.Errorf("dpl %d: gate type %#x, want a 64-bit interrupt gate 0xE", dpl, typ)
		}
		if g[5]&0x80 == 0 {
			t.Errorf("dpl %d: the gate is not present", dpl)
		}
		if got := int(g[5] >> 5 & 3); got != dpl {
			t.Errorf("gate DPL = %d, want %d", got, dpl)
		}
		if binary.LittleEndian.Uint32(g[12:]) != 0 {
			t.Errorf("dpl %d: the reserved word of the gate is not zero", dpl)
		}
	}
}
