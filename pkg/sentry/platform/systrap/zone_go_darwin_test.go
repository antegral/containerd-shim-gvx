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
	"debug/elf"
	"encoding/binary"
	"fmt"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/usermem"
)

// Layout of the synthetic Go executable. Every section lies in one segment
// that starts at goTestBase and holds the whole file.
const (
	goTestBase    = 0x10000
	goTestText    = goTestBase + 0x100
	goTestTextEnd = goTestText + 0x40
	goTestPCLN    = goTestBase + 0x200
	goTestModule  = goTestBase + 0x300
	goTestMap     = goTestBase + 0x400
	goTestFuncs   = goTestBase + 0x500
	goTestSize    = 0x700
)

// buildGoShapedELF returns an ET_EXEC image with the sections that
// parseGoImage reads: .text, .gopclntab with the Go 1.18 magic, .go.module with
// the code range words and a text section map, and .go.func with one function
// value.
func buildGoShapedELF(t *testing.T) []byte {
	t.Helper()
	img := make([]byte, goTestSize)
	le := binary.LittleEndian
	put := func(off int, vals ...uint64) {
		for i, v := range vals {
			le.PutUint64(img[off+8*i:], v)
		}
	}
	le.PutUint32(img[0x200:], 0xfffffff1)
	// Module data: pcHeader, then minpc, maxpc, text, etext, and the slice
	// header of the text section map.
	put(0x300, goTestPCLN)
	put(0x300+10*8, goTestText, goTestTextEnd, goTestText, goTestTextEnd)
	put(0x300+20*8, goTestMap, 1, 1)
	put(0x400, 0, 0x40, goTestText)
	put(0x500, goTestText+8, 0x1234)

	names := "\x00.text\x00.gopclntab\x00.go.module\x00.go.func\x00.shstrtab\x00"
	copy(img[0x600:], names)
	nameAt := func(s string) uint32 { return uint32(bytes.Index([]byte(names), []byte(s))) }

	copy(img, "\x7fELF\x02\x01\x01")
	le.PutUint16(img[16:], uint16(elf.ET_EXEC))
	le.PutUint16(img[18:], uint16(elf.EM_AARCH64))
	le.PutUint32(img[20:], 1)
	le.PutUint64(img[24:], goTestText)
	le.PutUint64(img[32:], 64)
	le.PutUint64(img[40:], 0x700)
	le.PutUint16(img[52:], 64)
	le.PutUint16(img[54:], 56)
	le.PutUint16(img[56:], 1)
	le.PutUint16(img[58:], 64)
	le.PutUint16(img[60:], 6)
	le.PutUint16(img[62:], 5)
	phdr := img[64:]
	le.PutUint32(phdr[0:], uint32(elf.PT_LOAD))
	le.PutUint32(phdr[4:], uint32(elf.PF_R|elf.PF_W|elf.PF_X))
	le.PutUint64(phdr[16:], goTestBase)
	le.PutUint64(phdr[32:], goTestSize)
	le.PutUint64(phdr[40:], goTestSize)

	type section struct {
		name       string
		typ        elf.SectionType
		addr, size uint64
		off        uint64
	}
	secs := []section{
		{".text", elf.SHT_PROGBITS, goTestText, 0x40, 0x100},
		{".gopclntab", elf.SHT_PROGBITS, goTestPCLN, 0x40, 0x200},
		{".go.module", elf.SHT_PROGBITS, goTestModule, 0x100, 0x300},
		{".go.func", elf.SHT_PROGBITS, goTestFuncs, 16, 0x500},
		{".shstrtab", elf.SHT_STRTAB, 0, uint64(len(names)), 0x600},
	}
	var shdrs bytes.Buffer
	shdrs.Write(make([]byte, 64))
	for _, s := range secs {
		h := make([]byte, 64)
		le.PutUint32(h[0:], nameAt(s.name))
		le.PutUint32(h[4:], uint32(s.typ))
		if s.addr != 0 {
			le.PutUint64(h[8:], uint64(elf.SHF_ALLOC))
		}
		le.PutUint64(h[16:], s.addr)
		le.PutUint64(h[24:], s.off)
		le.PutUint64(h[32:], s.size)
		shdrs.Write(h)
	}
	return append(img, shdrs.Bytes()...)
}

// imageMemory is a memory manager that serves CopyIn and CopyOut from one
// buffer that starts at base. Every other method panics.
type imageMemory struct {
	platform.MemoryManager
	base uint64
	mem  []byte
}

func (m *imageMemory) CopyIn(_ context.Context, addr hostarch.Addr, dst []byte, _ usermem.IOOpts) (int, error) {
	off := uint64(addr) - m.base
	if uint64(addr) < m.base || off+uint64(len(dst)) > uint64(len(m.mem)) {
		return 0, fmt.Errorf("read %#x outside the image", uint64(addr))
	}
	return copy(dst, m.mem[off:]), nil
}

func (m *imageMemory) CopyOut(_ context.Context, addr hostarch.Addr, src []byte, _ usermem.IOOpts) (int, error) {
	off := uint64(addr) - m.base
	if uint64(addr) < m.base || off+uint64(len(src)) > uint64(len(m.mem)) {
		return 0, fmt.Errorf("write %#x outside the image", uint64(addr))
	}
	return copy(m.mem[off:], src), nil
}

func (m *imageMemory) word(addr uint64) uint64 {
	return binary.LittleEndian.Uint64(m.mem[addr-m.base:])
}

func TestParseGoImageFindsTheWordsOfTheCodeRange(t *testing.T) {
	f, err := elf.NewFile(bytes.NewReader(buildGoShapedELF(t)))
	if err != nil {
		t.Fatalf("parse the synthetic executable: %v", err)
	}
	img := parseGoImage(f)
	if img == nil {
		t.Fatal("parseGoImage returned nil for a Go-shaped executable")
	}
	if img.textLo != goTestText || img.textHi != goTestTextEnd {
		t.Errorf("code range = [%#x, %#x), want [%#x, %#x)", img.textLo, img.textHi, goTestText, goTestTextEnd)
	}
	want := map[uint64]bool{
		goTestModule + 10*8: true, goTestModule + 11*8: true,
		goTestModule + 12*8: true, goTestModule + 13*8: true,
		goTestMap + 16: true,
	}
	if len(img.words) != len(want) {
		t.Errorf("words = %#x, want the %d addresses %v", img.words, len(want), want)
	}
	for _, w := range img.words {
		if !want[w] {
			t.Errorf("unexpected word address %#x", w)
		}
	}
	if len(img.ranges) != 1 || img.ranges[0] != [2]uint64{goTestFuncs, goTestFuncs + 16} {
		t.Errorf("ranges = %#x, want the section .go.func", img.ranges)
	}
}

func TestParseGoImageIgnoresAnExecutableWithoutTheSymbolTable(t *testing.T) {
	data := buildGoShapedELF(t)
	// Remove the magic of the symbol table header.
	binary.LittleEndian.PutUint32(data[0x200:], 0)
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse the synthetic executable: %v", err)
	}
	if img := parseGoImage(f); img != nil {
		t.Errorf("parseGoImage = %+v for an executable without the Go symbol table", img)
	}
}

func TestApplyAddsTheBiasToCodeAddressesOnce(t *testing.T) {
	data := buildGoShapedELF(t)
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse the synthetic executable: %v", err)
	}
	img := parseGoImage(f)
	if img == nil {
		t.Fatal("parseGoImage returned nil")
	}
	mm := &imageMemory{base: goTestBase, mem: append([]byte(nil), data[:goTestSize]...)}
	ctx := context.Background()

	changed, err := img.apply(ctx, mm)
	if err != nil || !changed {
		t.Fatalf("first apply = (%v, %v), want (true, nil)", changed, err)
	}
	for _, w := range []uint64{goTestModule + 10*8, goTestModule + 13*8, goTestMap + 16, goTestFuncs} {
		if got := mm.word(w); got < zoneBias || got >= zoneBias+0x100000 {
			t.Errorf("word at %#x = %#x, want a biased code address", w, got)
		}
	}
	if got := mm.word(goTestFuncs + 8); got != 0x1234 {
		t.Errorf("function value outside the code = %#x, want it unchanged", got)
	}
	if got := mm.word(goTestModule); got != goTestPCLN {
		t.Errorf("pcHeader word = %#x, want it unchanged", got)
	}

	before := append([]byte(nil), mm.mem...)
	changed, err = img.apply(ctx, mm)
	if err != nil || changed {
		t.Errorf("second apply = (%v, %v), want (false, nil)", changed, err)
	}
	if !bytes.Equal(before, mm.mem) {
		t.Error("second apply changed the memory")
	}
}
