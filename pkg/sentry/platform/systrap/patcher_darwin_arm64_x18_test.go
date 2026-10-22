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

//go:build darwin && arm64

package systrap

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
	"z.gfire.dev/gvx/pkg/sentry/loader/vdsodata"
)

// x18Corpus holds encodings that the toolchains of Linux emit for x18. Each
// word comes from the code of a musl or CPython build for arm64.
var x18Corpus = []struct {
	name string
	word uint32
	kind siteKind
}{
	{"mov x3, x18", 0xaa1203e3, siteX18},
	{"add x18, x18, #1", 0x91000652, siteX18},
	{"adc x12, x12, x18", 0x9a12018c, siteX18},
	{"adds x18, x18, x11", 0xab0b0252, siteX18},
	{"and x18, x18, #-8", 0x927df252, siteX18},
	{"ands x18, x1, #7", 0xf2400832, siteX18},
	{"asr x26, x18, #21", 0x9355fe5a, siteX18},
	{"ccmp w2, w18, #4, ne", 0x7a521044, siteX18},
	{"cmp x18, #0", 0xf100025f, siteX18},
	{"csel x18, x4, x18, eq", 0x9a920092, siteX18},
	{"cset x18, hs", 0x9a9f37f2, siteX18},
	{"extr w8, w18, w17, #17", 0x13914648, siteX18},
	{"fmov x18, d31", 0x9e6603f2, siteX18},
	{"ldp x30, x18, [x0, #24]", 0xa941c81e, siteX18},
	{"ldr x18, [sp, #72]", 0xf94027f2, siteX18},
	{"ldr x18, [x18, #3984]", 0xf947ca52, siteX18},
	{"ldrb w18, [x18, w30, uxtw]", 0x387e4a52, siteX18},
	{"ldrh w18, [x6, x3, lsl #1]", 0x786378d2, siteX18},
	{"ldurb w18, [x5, #-195]", 0x3853d0b2, siteX18},
	{"ldxrh w29, [x18]", 0x484f565d, siteX18},
	{"madd x22, x18, x16, x15", 0x9b103e56, siteX18},
	{"mov x18, #0x100000000", 0xd2c00032, siteX18},
	{"movk x18, #0x800, lsl #16", 0xf2a10012, siteX18},
	{"mul x18, x7, x2", 0x9b027cf2, siteX18},
	{"orr x11, x18, x11, lsl #32", 0xaa0b824b, siteX18},
	{"rev w18, w18", 0x5ac00a52, siteX18},
	{"smsubl x18, w26, w3, x18", 0x9b23cb52, siteX18},
	{"stnp s1, s14, [x18, #-104]", 0x2c333a41, siteX18},
	{"stp x18, x10, [sp, #104]", 0xa906abf2, siteX18},
	{"str xzr, [x18]", 0xf900025f, siteX18},
	{"strb wzr, [x18, #9]!", 0x38009e5f, siteX18},
	{"sub x18, x18, #1", 0xd1000652, siteX18},
	{"tst x18, #7", 0xf2400a5f, siteX18},
	{"ubfx x18, x19, #8, #4", 0xd3482e72, siteX18},
	{"stxr w18, w1, [x0]", 0x88127c01, siteX18},
	{"ld1 {v0.8b, v1.8b}, [x18]", 0x0c40a240, siteX18},
	{"ldadd x1, x2, [x18]", 0xf8210242, siteX18},
	{"swp x18, x2, [x0]", 0xf8328002, siteX18},
	{"cas x18, x2, [x0]", 0xc8b27c02, siteX18},
	{"adrp x18, #0x9f000", 0xf0000412, siteX18},
	{"ldr x18, #12", 0x58000072, siteX18},
	{"cbz x18, #12", 0xb4000072, siteX18Cond},
	{"cbnz w18, #12", 0x35000072, siteX18Cond},
	{"tbz x18, #63, #12", 0xb6f80072, siteX18Cond},
	{"br x18", 0xd61f0240, siteX18Jump},
	{"blr x18", 0xd63f0240, siteX18Jump},
	{"ret x18", 0xd65f0240, siteX18Jump},
}

func TestPlanX18CoversTheCorpus(t *testing.T) {
	for _, c := range x18Corpus {
		t.Run(c.name, func(t *testing.T) {
			p := planX18(c.word, 0x4_0000_1000)
			if p == nil {
				t.Fatalf("planX18(%#08x) found no x18 use", c.word)
			}
			if p.kind != c.kind {
				t.Fatalf("kind = %d, want %d", p.kind, c.kind)
			}
		})
	}
}

// TestPlanX18ChangesOnlyX18Fields checks the rewrite without the decoder that
// planX18 uses: the rewritten word may differ from the original only in
// register fields that held 18, and every such field must hold the scratch
// register afterwards.
func TestPlanX18ChangesOnlyX18Fields(t *testing.T) {
	for _, c := range x18Corpus {
		if c.kind != siteX18 {
			continue
		}
		p := planX18(c.word, 0x4_0000_1000)
		if p == nil || len(p.body) != 1 {
			continue // adrp and literal loads build constants, not renamed words.
		}
		got := p.body[0]
		changed := false
		for _, sh := range x18FieldShifts {
			was, now := fieldAt(c.word, sh), fieldAt(got, sh)
			if was == now {
				continue
			}
			changed = true
			if was != x18Reg || now != uint32(p.scratch) {
				t.Errorf("%s: field at bit %d changed from %d to %d, scratch is %d", c.name, sh, was, now, p.scratch)
			}
		}
		rest := c.word &^ (0x1f | 0x1f<<5 | 0x1f<<10 | 0x1f<<16)
		if got&^(0x1f|0x1f<<5|0x1f<<10|0x1f<<16) != rest {
			t.Errorf("%s: the rewrite changed bits outside the register fields: %#08x -> %#08x", c.name, c.word, got)
		}
		if !changed {
			t.Errorf("%s: the rewritten word equals the original", c.name)
		}
	}
}

// TestPlanX18ScratchIsFree checks that the borrowed register appears nowhere
// else in the instruction.
func TestPlanX18ScratchIsFree(t *testing.T) {
	for _, c := range x18Corpus {
		p := planX18(c.word, 0x4_0000_1000)
		if p == nil || p.kind == siteX18Jump || len(p.body) != 1 {
			continue
		}
		for _, sh := range x18FieldShifts {
			if fieldAt(c.word, sh) == uint32(p.scratch) {
				t.Errorf("%s: scratch x%d already appears at bit %d", c.name, p.scratch, sh)
			}
		}
	}
}

// TestPlanX18IgnoresOtherWords checks words where 18 is an immediate or a
// different register class.
func TestPlanX18IgnoresOtherWords(t *testing.T) {
	for _, c := range []struct {
		name string
		word uint32
	}{
		{"nop", 0xd503201f},
		{"add x0, x1, #0x480 (immediate bits equal 18)", 0x91000000 | 18<<10 | 1<<5},
		{"mov v18.16b, v2.16b", 0x4ea21c52},
		{"movz x0, #0x12", 0xd2800240},
		{"svc #0", 0xd4000001},
		{"stp x0, x1, [sp, #-16]!", 0xa9bf07e0},
	} {
		if p := planX18(c.word, 0x4_0000_1000); p != nil {
			t.Errorf("%s: planX18 returned a plan of kind %d", c.name, p.kind)
		}
	}
}

func TestPlanX18AddressForms(t *testing.T) {
	const site = 0x4_0000_1234
	adr := planX18(0x10000052, site) // adr x18, .+8
	if adr == nil || adr.kind != siteX18 {
		t.Fatalf("adr plan = %+v", adr)
	}
	if got := evalMovConst(adr.body); got != site+8 {
		t.Errorf("adr x18, .+8 loads %#x, want %#x", got, uint64(site+8))
	}
	adrp := planX18(0xf0000412, site) // adrp x18, +0x...
	if adrp == nil {
		t.Fatal("adrp x18 found no plan")
	}
	if got := evalMovConst(adrp.body[:len(adrp.body)]); got&0xfff != 0 {
		t.Errorf("adrp loads %#x, want a page address", got)
	}
}

// evalMovConst runs the movz and movk words of a constant sequence.
func evalMovConst(words []uint32) uint64 {
	var v uint64
	for _, w := range words {
		imm := uint64(w >> 5 & 0xffff)
		sh := uint(w>>21&3) * 16
		if w&0xff800000 == 0xd2800000 {
			v = imm << sh
		} else if w&0xff800000 == 0xf2800000 {
			v = v&^(0xffff<<sh) | imm<<sh
		}
	}
	return v
}

func TestEncodeX18SlotGenericLayout(t *testing.T) {
	const slotVA, site = 0x4_0100_0000, 0x4_0000_1000
	p := planX18(0xaa1203e3, site) // mov x3, x18
	if p == nil {
		t.Fatal("no plan")
	}
	buf := make([]byte, p.slotSize())
	if err := encodeX18Slot(buf, slotVA, site, p); err != nil {
		t.Fatal(err)
	}
	want := p.slotSize() / 4
	if want != 10 {
		t.Fatalf("generic slot has %d words, want 10", want)
	}
	words := make([]uint32, want)
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(buf[i*4:])
	}
	s := uint32(p.scratch)
	ptr := sysmsgPointer()
	expect := []uint32{
		ptr[0], ptr[1],
		strFromSysmsg(p.scratch, spillOffset),
		ldrFromSysmsg(p.scratch, x18Offset),
		p.body[0],
		ptr[0], ptr[1],
		strFromSysmsg(p.scratch, x18Offset),
		ldrFromSysmsg(p.scratch, spillOffset),
	}
	for i, w := range expect {
		if words[i] != w {
			t.Errorf("word %d = %#08x, want %#08x", i, words[i], w)
		}
	}
	back, ok := decodeBranch(slotVA+9*4, words[9])
	if !ok || back != site+4 {
		t.Errorf("the slot returns to %#x, want %#x", back, uint64(site+4))
	}
	// The scratch register must never be the register that holds the sysmsg pointer.
	if s == x18Reg {
		t.Error("the scratch register is x18")
	}
}

func TestEncodeX18SlotRejectsShortBuffer(t *testing.T) {
	p := planX18(0xaa1203e3, 0x4_0000_1000)
	if err := encodeX18Slot(make([]byte, 8), 0x4_0100_0000, 0x4_0000_1000, p); err == nil {
		t.Fatal("encodeX18Slot accepted a buffer that is too small")
	}
	if err := encodeX18Slot(make([]byte, 64), 0x4_0100_0000, 0x4_0000_1000, &x18Plan{kind: siteX18Jump}); err == nil {
		t.Fatal("encodeX18Slot built a slot for a jump through x18")
	}
}

func TestX18RestartPhases(t *testing.T) {
	const body = 1
	end := uint32(x18SlotHead + 4*body)
	for _, c := range []struct {
		name     string
		kind     siteKind
		off      uint32
		restart  uint32
		wantBody bool
		wantOK   bool
	}{
		{"generic head, first word", siteX18, 0, 0, false, true},
		{"generic head, load", siteX18, 12, 0, false, true},
		{"generic body", siteX18, x18SlotHead, 0, true, true},
		{"generic tail, store", siteX18, end + 8, end, false, true},
		{"generic tail, restore", siteX18, end + 12, end, false, true},
		{"generic closing branch", siteX18, end + 16, 0, false, false},
		{"conditional head", siteX18Cond, 8, 0, false, true},
		{"conditional test", siteX18Cond, 16, 0, false, false},
		{"conditional fall-through restore", siteX18Cond, x18CondFall + 8, x18CondFall, false, true},
		{"conditional taken restore", siteX18Cond, x18CondTaken + 4, x18CondTaken, false, true},
		{"conditional taken branch", siteX18Cond, x18CondTaken + 12, 0, false, false},
	} {
		restart, body2, ok := x18Restart(c.kind, body, c.off)
		if ok != c.wantOK || body2 != c.wantBody || (ok && !body2 && restart != c.restart) {
			t.Errorf("%s: x18Restart = (%d, %v, %v), want (%d, %v, %v)", c.name, restart, body2, ok, c.restart, c.wantBody, c.wantOK)
		}
	}
}

// TestLiteralWordsMarksPools checks that a word that an ldr literal reads is
// left alone by the scan.
func TestLiteralWordsMarksPools(t *testing.T) {
	// ldr x0, .+8 at offset 0 reads offsets 8 and 12. ldr q0, .+16 at offset 4 reads offsets 20..32.
	code := words(0x58000040, 0x9c000080, 0x12345678, 0x12345679, insnNOP, 0, 0, 0, 0)
	marks := literalWords(code)
	for _, off := range []int{8, 12, 20, 24, 28, 32} {
		if _, ok := marks[off]; !ok {
			t.Errorf("offset %d is not marked as literal data", off)
		}
	}
	if _, ok := marks[4]; ok {
		t.Error("offset 4 is marked as literal data")
	}
}

func TestScanX18SkipsClaimedAndLiteralWords(t *testing.T) {
	// ldr w0, .+8 reads only the word at offset 8. That word looks like `mov x3, x18` and must stay intact.
	code := words(0x18000040, 0xd65f03c0, 0xaa1203e3, 0xaa1203e3)
	sites := scanX18(code, 0x4_0000_0000, func(off int) bool { return off == 12 })
	if len(sites) != 0 {
		t.Fatalf("scanX18 found %d sites, want none: the pool word and the claimed word are skipped", len(sites))
	}
	sites = scanX18(code, 0x4_0000_0000, func(int) bool { return false })
	if len(sites) != 1 || sites[0].Offset != 12 {
		t.Fatalf("scanX18 = %+v, want one site at offset 12", sites)
	}
}

// TestVDSOHasNoX18 pins the invariant that lets the patcher skip the vDSO: the
// image that the Sentry maps into every guest never names x18.
func TestVDSOHasNoX18(t *testing.T) {
	image := vdsodata.Binary
	for off := 0; off+4 <= len(image); off += 4 {
		w := binary.LittleEndian.Uint32(image[off:])
		var raw [4]byte
		binary.LittleEndian.PutUint32(raw[:], w)
		inst, err := arm64asm.Decode(raw[:])
		if err != nil {
			continue
		}
		if x18RegX.MatchString(inst.String()) || x18RegW.MatchString(inst.String()) {
			// Data words can decode as instructions, so only code counts. The
			// code of the vDSO is the first section that holds text.
			if off >= vdsoTextStart && off < vdsoTextEnd {
				t.Errorf("the vDSO names x18 at offset %#x: %s", off, inst)
			}
		}
	}
}

// vdsoTextStart and vdsoTextEnd bound the code of the vDSO image. The test
// reads them from the section headers.
var vdsoTextStart, vdsoTextEnd = func() (int, int) {
	ci, err := parseCodeImage(bytes.NewReader(vdsodata.Binary))
	if err != nil || len(ci.exec) == 0 {
		return 0, 0
	}
	lo, hi := ci.exec[0].lo, ci.exec[0].hi
	for _, s := range ci.exec {
		lo, hi = min(lo, s.lo), max(hi, s.hi)
	}
	// The prelinked vDSO address of the first load segment maps file offset 0.
	return int(lo - ci.loads[0].vaddr + ci.loads[0].off), int(hi - ci.loads[0].vaddr + ci.loads[0].off)
}()
