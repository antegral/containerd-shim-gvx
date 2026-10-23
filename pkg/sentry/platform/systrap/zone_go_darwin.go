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
	"debug/elf"
	"encoding/binary"
	"fmt"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/usermem"
)

// The Go runtime compares every program counter on a stack with the code
// range in its module data. It resolves the function of a counter with the
// symbol table in the section .gopclntab. The code of a zone image runs at the
// biased address, so every return address on a stack is biased. The module
// data and the symbol table hold the unbiased range. The zone mode therefore
// adds the bias to the words that describe the code range. It also adds the
// bias to the function values in the section .go.func. The runtime resolves a
// function value like a return address.

// Magic numbers of the symbol table header for Go 1.18 and later.
var goPCHeaderMagics = [...]uint32{0xfffffff0, 0xfffffff1}

// goImage is the part of a Go executable that the zone mode adjusts.
type goImage struct {
	// textLo and textHi bound the code of the executable, as guest addresses.
	textLo, textHi uint64
	// pcHeader is the address of the header of the symbol table.
	pcHeader uint64
	// words lists the guest addresses of the words that get the bias.
	words []uint64
	// ranges lists the guest ranges in which every aligned word that points
	// into the code gets the bias.
	ranges [][2]uint64
}

// parseGoImage returns the description of a Go executable, or nil for another
// kind of executable. It reads the section headers and the module data from the
// file.
func parseGoImage(f *elf.File) *goImage {
	text, pclntab := f.Section(".text"), f.Section(".gopclntab")
	if f.Type != elf.ET_EXEC || text == nil || pclntab == nil || pclntab.Size < 64 {
		return nil
	}
	head, err := pclntab.Data()
	if err != nil || len(head) < 64 {
		return nil
	}
	magic := binary.LittleEndian.Uint32(head)
	found := false
	for _, m := range goPCHeaderMagics {
		found = found || magic == m
	}
	img := &goImage{textLo: text.Addr, textHi: text.Addr + text.Size, pcHeader: pclntab.Addr}
	if !found {
		return nil
	}
	if md, ok := findModuleData(f, img.pcHeader); ok {
		img.addModuleData(f, md)
	}
	if len(img.words) == 0 {
		return nil
	}
	if sec := f.Section(".go.func"); sec != nil && sec.Size > 0 {
		img.ranges = append(img.ranges, [2]uint64{sec.Addr, sec.Addr + sec.Size})
	}
	return img
}

// moduleDataBytes bounds the scan of the module data for words of the code
// range. The words minpc, maxpc, text, and etext lie in its first 256 bytes.
const moduleDataBytes = 256

// findModuleData returns the guest address of the first module data. The
// symbol table names it. A stripped executable has no symbol table. The search
// then uses the section .go.module, and last the word that points to the
// header of the symbol table.
func findModuleData(f *elf.File, pcHeader uint64) (uint64, bool) {
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name == "runtime.firstmoduledata" {
				return s.Value, true
			}
		}
	}
	if sec := f.Section(".go.module"); sec != nil && sec.Size >= moduleDataBytes {
		return sec.Addr, true
	}
	for _, name := range []string{".noptrdata", ".data"} {
		sec := f.Section(name)
		if sec == nil || sec.Type == elf.SHT_NOBITS {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		for off := 0; off+8 <= len(data); off += 8 {
			if binary.LittleEndian.Uint64(data[off:]) == pcHeader {
				return sec.Addr + uint64(off), true
			}
		}
	}
	return 0, false
}

// addModuleData lists the words of the module data at md that hold a code
// address, and the base address of its text section map.
func (img *goImage) addModuleData(f *elf.File, md uint64) {
	words := readImageWords(f, md, moduleDataBytes/8)
	for i, w := range words {
		if w >= img.textLo && w <= img.textHi {
			img.words = append(img.words, md+uint64(i)*8)
		}
	}
	// The text section map is a slice of {vaddr, end, baseaddr}. The slice
	// header holds the pointer, the length, and the capacity.
	for i := 0; i+2 < len(words); i++ {
		if words[i+1] != 1 || words[i+2] != 1 {
			continue
		}
		if elem := readImageWords(f, words[i], 3); len(elem) == 3 && elem[0] == 0 && elem[2] >= img.textLo && elem[2] <= img.textHi {
			img.words = append(img.words, words[i]+16)
		}
	}
}

// readImageWords reads n little-endian words that start at the guest address
// addr from the file. It returns nil when no loadable segment holds the range.
func readImageWords(f *elf.File, addr uint64, n int) []uint64 {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || addr < p.Vaddr || addr+uint64(n)*8 > p.Vaddr+p.Filesz {
			continue
		}
		buf := make([]byte, n*8)
		if _, err := p.ReadAt(buf, int64(addr-p.Vaddr)); err != nil {
			return nil
		}
		words := make([]uint64, n)
		for i := range words {
			words[i] = binary.LittleEndian.Uint64(buf[i*8:])
		}
		return words
	}
	return nil
}

// prepareZoneImage adds the bias to the code range of a Go executable in the
// guest memory. It runs once for each address space. It runs when the first
// block of the zone gets patched, before the guest runs an instruction of the
// image. A forked address space inherits the adjusted words, so the function
// checks the first word first.
func (as *addressSpace) prepareZoneImage(ctx context.Context, mm platform.MemoryManager, base uint64) {
	as.mu.Lock()
	done := as.zoneImageDone
	as.zoneImageDone = true
	as.mu.Unlock()
	if done {
		return
	}
	provider, ok := mm.(platform.ExecImageProvider)
	if !ok {
		return
	}
	info := provider.ExecImageAt(ctx, hostarch.Addr(as.p.guestAddr(base)))
	if info.Kind != platform.MappingFile || info.File == nil {
		return
	}
	defer info.Release()
	f, err := elf.NewFile(info.File)
	if err != nil {
		return
	}
	img := parseGoImage(f)
	if img == nil {
		return
	}
	adjusted, err := img.apply(ctx, mm)
	if err != nil {
		log.Warningf("systrap: adjust the Go symbol tables of the zone image: %v", err)
		return
	}
	as.mu.Lock()
	as.goText = [2]uint64{img.textLo, img.textHi}
	as.mu.Unlock()
	if adjusted {
		log.Debugf("systrap: added the zone bias to the code range of a Go executable (%d words, %d ranges)", len(img.words), len(img.ranges))
	}
}

// apply adds the bias to the words of the image in the guest memory. It
// reports false when an earlier address space already did that.
func (img *goImage) apply(ctx context.Context, mm platform.MemoryManager) (bool, error) {
	opts := usermem.IOOpts{IgnorePermissions: true}
	var first [8]byte
	if _, err := mm.CopyIn(ctx, hostarch.Addr(img.words[0]), first[:], opts); err != nil {
		return false, fmt.Errorf("read the symbol table header at %#x: %w", img.words[0], err)
	}
	if binary.LittleEndian.Uint64(first[:]) >= zoneBias {
		// The word holds a biased address already, as in a forked address space.
		return false, nil
	}
	for _, addr := range img.words {
		if err := addBias(ctx, mm, addr, 8, img.textLo, img.textHi); err != nil {
			return false, err
		}
	}
	for _, r := range img.ranges {
		if err := addBias(ctx, mm, r[0], r[1]-r[0], img.textLo, img.textHi); err != nil {
			return false, err
		}
	}
	return true, nil
}

// addBias adds the zone bias to every aligned word in [addr, addr+size) whose
// value lies in [lo, hi].
func addBias(ctx context.Context, mm platform.MemoryManager, addr, size, lo, hi uint64) error {
	opts := usermem.IOOpts{IgnorePermissions: true}
	buf := make([]byte, size)
	if _, err := mm.CopyIn(ctx, hostarch.Addr(addr), buf, opts); err != nil {
		return fmt.Errorf("read %#x: %w", addr, err)
	}
	changed := false
	for off := 0; off+8 <= len(buf); off += 8 {
		if w := binary.LittleEndian.Uint64(buf[off:]); w >= lo && w <= hi {
			binary.LittleEndian.PutUint64(buf[off:], w+zoneBias)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if _, err := mm.CopyOut(ctx, hostarch.Addr(addr), buf, opts); err != nil {
		return fmt.Errorf("write %#x: %w", addr, err)
	}
	return nil
}

// isGoCode reports whether the guest address a lies in the code of a Go image.
func (as *addressSpace) isGoCode(a uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.goText[1] != 0 && a >= as.goText[0] && a < as.goText[1]
}
