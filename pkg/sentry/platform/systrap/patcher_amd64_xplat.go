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

//go:build darwin || windows

package systrap

import (
	"golang.org/x/arch/x86/x86asm"
)

// The amd64 patcher rewrites the segment override prefixes of a Linux guest.
//
// A Linux amd64 program reaches its thread-local storage through the FS base,
// for example `mov %fs:0, %rax`. Rosetta cannot set the FS base of a thread
// and supports no wrfsbase instruction. A `%fs:` access therefore uses base 0
// and reads the wrong memory. Rosetta does let the stub set the GS base. The
// patcher changes each FS prefix byte 0x64 into the GS prefix byte 0x65 in an
// executable copy of the guest code page. The stub then loads the guest FS
// base into the GS base, and every rewritten access reaches the guest TLS.
//
// The same trick means the guest cannot use GS for its own purposes. An
// instruction with a GS override on a memory operand becomes ud2, so the
// guest faults instead of reading the guest TLS by mistake.
//
// The patcher decodes linearly, because x86 has no way to find instruction
// starts without symbols. The decoder starts a few bytes before the page and
// resynchronizes after a few instructions. A rare data byte inside code can
// look like a prefix and then receive a rewrite. This is a known limit. Call
// x86Edits on the original guest bytes and never on already rewritten bytes,
// because a rewritten FS access looks like a GS access.

const (
	// x86PrefixFS is the legacy prefix byte of the FS segment override.
	x86PrefixFS = 0x64

	// x86PrefixGS is the legacy prefix byte of the GS segment override.
	x86PrefixGS = 0x65

	// x86MaxBefore is the number of bytes before a block that the caller
	// SHOULD pass to x86Edits. It is four times the longest instruction, so
	// the decoder has time to resynchronize before the first byte of the block.
	x86MaxBefore = 64

	// x86MaxAfter is the number of bytes after a block that the caller SHOULD
	// pass to x86Edits. It is the longest x86 instruction minus one byte.
	x86MaxAfter = 15

	// x86Int3 is the one-byte trap that x86Apply writes when a block ends in
	// the first byte of an unsupported instruction.
	x86Int3 = 0xCC

	// x86UD2First and x86UD2Second are the two bytes of the ud2 instruction.
	x86UD2First  = 0x0F
	x86UD2Second = 0x0B

	// x86MaxPrefixes is the largest number of prefix entries of one decoded
	// instruction.
	x86MaxPrefixes = 14
)

// x86EditKind classifies an edit that x86Edits returns.
type x86EditKind uint8

const (
	// x86EditFSToGS changes an FS prefix byte 0x64 into 0x65. Offset is the
	// offset of the prefix byte.
	x86EditFSToGS x86EditKind = iota + 1

	// x86EditUnsupportedGS marks an instruction with a GS override on a memory
	// operand. The engine uses GS for the guest FS base, so the guest cannot
	// use it. Offset is the first byte of the instruction.
	x86EditUnsupportedGS
)

// x86Edit is one in-place byte edit of a code block.
type x86Edit struct {
	// Offset is the position of the edited byte in the block.
	Offset int

	// Kind tells x86Apply which bytes to write.
	Kind x86EditKind

	// Len is the length of the instruction in bytes. The instruction can end
	// after the block.
	Len int
}

// x86IsLegacyPrefix reports whether b is a legacy prefix byte of x86-64.
func x86IsLegacyPrefix(b byte) bool {
	switch b {
	case 0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, x86PrefixFS, x86PrefixGS:
		return true
	}
	return false
}

// x86IsVEXLead reports whether b starts a VEX or EVEX encoding in 64-bit mode.
func x86IsVEXLead(b byte) bool {
	return b == 0xC4 || b == 0xC5 || b == 0x62
}

// x86HasMem returns the segment of the first memory operand of the decoded
// instruction. It returns false when the instruction has no memory operand.
func x86HasMem(inst *x86asm.Inst) (seg x86asm.Reg, ok bool) {
	for _, a := range inst.Args {
		if m, isMem := a.(x86asm.Mem); isMem {
			return m.Segment, true
		}
	}
	return 0, false
}

// x86Decode decodes the instruction at buf[pos:]. The decoder rejects a
// segment prefix in front of a VEX or EVEX encoding, but hardware accepts it.
// For that case x86Decode decodes the encoding behind the prefix and adds one
// to the length. It returns false when the bytes are not an instruction.
func x86Decode(buf []byte, pos int) (inst x86asm.Inst, n int, vexSeg bool, ok bool) {
	inst, err := x86asm.Decode(buf[pos:], 64)
	if err == nil && inst.Op != 0 && inst.Len > 0 {
		return inst, inst.Len, false, true
	}
	b := buf[pos]
	if (b == x86PrefixFS || b == x86PrefixGS) && pos+1 < len(buf) && x86IsVEXLead(buf[pos+1]) {
		inst, err = x86asm.Decode(buf[pos+1:], 64)
		if err == nil && inst.Op != 0 && inst.Len > 0 {
			return inst, inst.Len + 1, true, true
		}
	}
	return x86asm.Inst{}, 0, false, false
}

// x86FSOffset returns the offset in buf of the FS prefix byte that applies to
// the instruction at pos, or -1 when the instruction has no effective FS
// override. The decoder marks a prefix as ignored when a later prefix
// overrides it, so only the last segment prefix counts.
func x86FSOffset(buf []byte, pos, n int, inst *x86asm.Inst, vexSeg bool) int {
	if vexSeg {
		if buf[pos] != x86PrefixFS {
			return -1
		}
		if _, hasMem := x86HasMem(inst); !hasMem {
			return -1
		}
		return pos
	}
	for k, p := range inst.Prefix {
		if p == 0 || k >= x86MaxPrefixes {
			break
		}
		if p&(x86asm.PrefixIgnored|x86asm.PrefixInvalid) != 0 {
			continue
		}
		if byte(p) == x86PrefixFS && k < n && buf[pos+k] == x86PrefixFS {
			return pos + k
		}
	}
	seg, hasMem := x86HasMem(inst)
	if !hasMem || seg != x86asm.FS {
		return -1
	}
	// The decoder reports an FS memory operand without a matching prefix
	// entry. Use the last FS byte among the leading prefix bytes.
	off := -1
	for j := pos; j < pos+n; j++ {
		b := buf[j]
		if b >= 0x40 && b <= 0x4F || x86IsLegacyPrefix(b) {
			if b == x86PrefixFS {
				off = j
			}
			continue
		}
		break
	}
	return off
}

// x86HasGS reports whether the instruction has a GS override on a memory
// operand.
func x86HasGS(buf []byte, pos int, inst *x86asm.Inst, vexSeg bool) bool {
	seg, hasMem := x86HasMem(inst)
	if !hasMem {
		return false
	}
	if vexSeg {
		return buf[pos] == x86PrefixGS
	}
	return seg == x86asm.GS
}

// x86Edits returns the in-place byte edits that make the code block run
// correctly inside a Rosetta task.
//
// The block is one page of guest code. The before bytes precede the block in
// the guest address space and the after bytes follow it. Both can be empty.
// The decoder starts at the first byte of before so that it synchronizes with
// the instruction boundaries before the block.
//
// An FS edit covers every FS prefix byte that lies inside the block, even when
// the instruction starts in before. The previous block cannot edit that byte.
// A GS edit covers only instructions that start inside the block.
func x86Edits(block, before, after []byte) []x86Edit {
	start := len(before)
	end := start + len(block)
	buf := make([]byte, 0, end+len(after))
	buf = append(buf, before...)
	buf = append(buf, block...)
	buf = append(buf, after...)

	var edits []x86Edit
	for pos := 0; pos < end; {
		inst, n, vexSeg, ok := x86Decode(buf, pos)
		if !ok {
			pos++
			continue
		}
		if x86HasGS(buf, pos, &inst, vexSeg) {
			if pos >= start {
				edits = append(edits, x86Edit{Offset: pos - start, Kind: x86EditUnsupportedGS, Len: n})
			}
		} else if off := x86FSOffset(buf, pos, n, &inst, vexSeg); off >= start && off < end {
			edits = append(edits, x86Edit{Offset: off - start, Kind: x86EditFSToGS, Len: n})
		}
		pos += n
	}
	return edits
}

// x86Apply writes the edits into block and returns the number of
// x86EditUnsupportedGS edits.
//
// An unsupported instruction becomes ud2 when both bytes fit into the block.
// An instruction that starts in the last byte of the block becomes int3. The
// rest of that instruction lies in the next block, and int3 traps before the
// CPU reads it.
func x86Apply(block []byte, edits []x86Edit) (unsupported int) {
	for _, e := range edits {
		switch e.Kind {
		case x86EditFSToGS:
			block[e.Offset] = x86PrefixGS
		case x86EditUnsupportedGS:
			unsupported++
			if e.Offset+1 < len(block) {
				block[e.Offset] = x86UD2First
				block[e.Offset+1] = x86UD2Second
			} else {
				block[e.Offset] = x86Int3
			}
		}
	}
	return unsupported
}
