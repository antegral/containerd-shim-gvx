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
	"bytes"
	"reflect"
	"testing"
)

// x86CompiledFunction holds the machine code of two C functions that use
// thread-local variables and the stack protector. Apple clang 21 compiled it with
// "-target x86_64-unknown-linux-gnu -O2 -fno-pic -ftls-model=local-exec
// -fstack-protector-all". Relocation fields are zero. The code contains
// 0x64 bytes that are immediates, for example in a movabs and in cmp.
var x86CompiledFunction = []byte{
	0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec,
	0x40, 0x64, 0x4c, 0x8b, 0x3c, 0x25, 0x00, 0x00, 0x00, 0x00, 0x64, 0x48,
	0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x38,
	0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x85, 0xf6, 0x7e,
	0x69, 0x48, 0x89, 0xd3, 0x49, 0x89, 0xfe, 0x41, 0x89, 0xf4, 0x45, 0x31,
	0xed, 0xeb, 0x09, 0x90, 0x49, 0xff, 0xc5, 0x4d, 0x39, 0xec, 0x74, 0x4a,
	0x48, 0x89, 0xc1, 0x4b, 0x8b, 0x04, 0xee, 0x89, 0xc2, 0x0f, 0xaf, 0xd3,
	0x44, 0x89, 0xee, 0x83, 0xe6, 0x1f, 0x88, 0x14, 0x34, 0x64, 0x48, 0x63,
	0x14, 0x25, 0x00, 0x00, 0x00, 0x00, 0x48, 0x31, 0xd0, 0x48, 0x01, 0xc8,
	0x8d, 0x4a, 0x01, 0x64, 0x89, 0x0c, 0x25, 0x00, 0x00, 0x00, 0x00, 0x48,
	0x3d, 0xe9, 0x03, 0x00, 0x00, 0x7c, 0xc1, 0x48, 0x89, 0xc7, 0xe8, 0x00,
	0x00, 0x00, 0x00, 0x64, 0x48, 0x03, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
	0xeb, 0xae, 0x48, 0x0f, 0xbe, 0x4c, 0x24, 0x03, 0xeb, 0x02, 0x31, 0xc9,
	0x64, 0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x64, 0x48, 0x8b,
	0x14, 0x25, 0x28, 0x00, 0x00, 0x00, 0x48, 0x3b, 0x54, 0x24, 0x38, 0x75,
	0x1b, 0x49, 0x8d, 0x97, 0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 0xc8, 0x48,
	0x01, 0xd0, 0x48, 0x83, 0xc4, 0x40, 0x5b, 0x41, 0x5c, 0x41, 0x5d, 0x41,
	0x5e, 0x41, 0x5f, 0xc3, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x2e,
	0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xec, 0x48,
	0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44,
	0x24, 0x40, 0x0f, 0x57, 0xc0, 0x0f, 0x29, 0x44, 0x24, 0x30, 0x0f, 0x29,
	0x44, 0x24, 0x20, 0x0f, 0x29, 0x44, 0x24, 0x10, 0x0f, 0x29, 0x04, 0x24,
	0x85, 0xf6, 0x7e, 0x6c, 0x64, 0x48, 0x8b, 0x0c, 0x25, 0x00, 0x00, 0x00,
	0x00, 0x64, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x89, 0xf2, 0x31,
	0xf6, 0x49, 0xb8, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0xeb,
	0x0e, 0x0f, 0x1f, 0x00, 0x83, 0xf0, 0x64, 0x48, 0xff, 0xc6, 0x48, 0x39,
	0xf2, 0x74, 0x25, 0x4c, 0x8b, 0x0c, 0xf7, 0x4c, 0x63, 0xd0, 0x4d, 0x0f,
	0xaf, 0xd1, 0x49, 0x01, 0xca, 0x41, 0x89, 0xf3, 0x41, 0x83, 0xe3, 0x07,
	0x4e, 0x01, 0x14, 0xdc, 0x49, 0x83, 0xf9, 0x64, 0x75, 0xd6, 0x4c, 0x89,
	0x04, 0x24, 0xeb, 0xd0, 0x64, 0x89, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
	0x48, 0x8b, 0x44, 0x24, 0x08, 0x48, 0x03, 0x04, 0x24, 0x48, 0x03, 0x44,
	0x24, 0x38, 0xeb, 0x02, 0x31, 0xc0, 0x64, 0x48, 0x8b, 0x0c, 0x25, 0x28,
	0x00, 0x00, 0x00, 0x48, 0x3b, 0x4c, 0x24, 0x40, 0x75, 0x05, 0x48, 0x83,
	0xc4, 0x48, 0xc3, 0xe8, 0x00, 0x00, 0x00, 0x00,
}

// x86CompiledFSOffsets lists the offsets of every FS prefix byte in
// x86CompiledFunction. The list comes from the objdump output of the object.
var x86CompiledFSOffsets = []int{13, 22, 36, 93, 111, 135, 156, 165, 228, 268, 277, 352, 378}

// x86Starts returns the offset of every instruction that a linear decode of
// buf finds. The decode uses the same rules as x86Edits.
func x86Starts(buf []byte) (starts []int, lens map[int]int) {
	lens = make(map[int]int)
	for pos := 0; pos < len(buf); {
		_, n, _, ok := x86Decode(buf, pos)
		if !ok {
			pos++
			continue
		}
		starts = append(starts, pos)
		lens[pos] = n
		pos += n
	}
	return starts, lens
}

// x86FSInRange reports whether the decoder sees an effective FS prefix byte
// inside buf[from:to].
func x86FSInRange(buf []byte, from, to int) bool {
	for pos := 0; pos < to; {
		inst, n, vexSeg, ok := x86Decode(buf, pos)
		if !ok {
			pos++
			continue
		}
		if off := x86FSOffset(buf, pos, n, &inst, vexSeg); off >= from && off < to {
			return true
		}
		pos += n
	}
	return false
}

// x86CheckApply applies the edits of block to a copy and verifies the result.
// It checks that no FS override remains, that the instruction boundaries stay
// the same and that a second application changes nothing. It returns the
// patched block and the unsupported count.
func x86CheckApply(t *testing.T, block, before, after []byte) ([]byte, int) {
	t.Helper()
	edits := x86Edits(block, before, after)
	patched := bytes.Clone(block)
	unsupported := x86Apply(patched, edits)

	wantUnsupported := 0
	for _, e := range edits {
		if e.Kind == x86EditUnsupportedGS {
			wantUnsupported++
		}
	}
	if unsupported != wantUnsupported {
		t.Errorf("x86Apply returned %d unsupported, want %d", unsupported, wantUnsupported)
	}

	again := bytes.Clone(patched)
	x86Apply(again, edits)
	if !bytes.Equal(patched, again) {
		t.Errorf("second x86Apply changed the block:\n got % x\nwant % x", again, patched)
	}

	if wantUnsupported == 0 {
		beforeStarts, beforeLens := x86Starts(joinBytes(before, block, after))
		afterStarts, afterLens := x86Starts(joinBytes(before, patched, after))
		if !reflect.DeepEqual(beforeStarts, afterStarts) || !reflect.DeepEqual(beforeLens, afterLens) {
			t.Errorf("instruction boundaries changed after x86Apply")
		}
		if x86FSInRange(joinBytes(before, patched, after), len(before), len(before)+len(patched)) {
			t.Errorf("an FS override remains in the patched block % x", patched)
		}
	}
	return patched, unsupported
}

func joinBytes(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

func TestX86EditsInstructionForms(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block []byte
		want  []x86Edit
	}{
		{
			name:  "mov rax from fs 0",
			block: []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00},
			want:  []x86Edit{{Offset: 0, Kind: x86EditFSToGS, Len: 9}},
		},
		{
			name:  "mov rax from fs rax",
			block: []byte{0x64, 0x48, 0x8b, 0x00},
			want:  []x86Edit{{Offset: 0, Kind: x86EditFSToGS, Len: 4}},
		},
		{
			name:  "mov fs minus 8 from rax",
			block: []byte{0x64, 0x48, 0x89, 0x04, 0x25, 0xf8, 0xff, 0xff, 0xff},
			want:  []x86Edit{{Offset: 0, Kind: x86EditFSToGS, Len: 9}},
		},
		{
			name:  "stack protector load",
			block: []byte{0x64, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00},
			want:  []x86Edit{{Offset: 0, Kind: x86EditFSToGS, Len: 8}},
		},
		{
			name:  "xor rcx with fs 0x28",
			block: []byte{0x64, 0x48, 0x33, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00},
			want:  []x86Edit{{Offset: 0, Kind: x86EditFSToGS, Len: 9}},
		},
		{
			name:  "lea with fs",
			block: []byte{0x64, 0x48, 0x8d, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00},
			want:  []x86Edit{{Offset: 0, Kind: x86EditFSToGS, Len: 9}},
		},
		{
			name:  "fs after other prefix",
			block: []byte{0x66, 0x64, 0x8b, 0x00},
			want:  []x86Edit{{Offset: 1, Kind: x86EditFSToGS, Len: 4}},
		},
		{
			name:  "fs then ignored fs",
			block: []byte{0x64, 0x64, 0x48, 0x8b, 0x00},
			want:  []x86Edit{{Offset: 1, Kind: x86EditFSToGS, Len: 5}},
		},
		{
			name:  "gs then fs",
			block: []byte{0x65, 0x64, 0x48, 0x8b, 0x00},
			want:  []x86Edit{{Offset: 1, Kind: x86EditFSToGS, Len: 5}},
		},
		{
			name:  "fs before vex load",
			block: []byte{0x64, 0xc5, 0xfa, 0x6f, 0x00},
			want:  []x86Edit{{Offset: 0, Kind: x86EditFSToGS, Len: 5}},
		},
		{
			name:  "fs on rep movsb",
			block: []byte{0xf3, 0x64, 0xa4},
			want:  []x86Edit{{Offset: 1, Kind: x86EditFSToGS, Len: 3}},
		},
		{
			name:  "mov eax immediate 0x64",
			block: []byte{0xb8, 0x64, 0x00, 0x00, 0x00},
		},
		{
			name:  "mov rax immediate 0x64646464",
			block: []byte{0x48, 0xc7, 0xc0, 0x64, 0x64, 0x64, 0x64},
		},
		{
			name:  "movabs of all 0x64",
			block: []byte{0x48, 0xb8, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64},
		},
		{
			name:  "movabs with 0x64 in the middle",
			block: []byte{0x48, 0xb8, 0x11, 0x22, 0x64, 0x88, 0x99, 0xaa, 0xbb, 0xcc},
		},
		{
			name:  "cmp with 0x64 displacement",
			block: []byte{0x48, 0x83, 0xf9, 0x64},
		},
		{
			name:  "gs load",
			block: []byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00},
			want:  []x86Edit{{Offset: 0, Kind: x86EditUnsupportedGS, Len: 9}},
		},
		{
			name:  "fs then gs",
			block: []byte{0x64, 0x65, 0x48, 0x8b, 0x00},
			want:  []x86Edit{{Offset: 0, Kind: x86EditUnsupportedGS, Len: 5}},
		},
		{
			name:  "gs before vex load",
			block: []byte{0x65, 0xc5, 0xfa, 0x6f, 0x00},
			want:  []x86Edit{{Offset: 0, Kind: x86EditUnsupportedGS, Len: 5}},
		},
		{
			name:  "gs prefix without memory operand",
			block: []byte{0x65, 0x90},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := x86Edits(tc.block, nil, nil)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("x86Edits() = %+v, want %+v", got, tc.want)
			}
			x86CheckApply(t, tc.block, nil, nil)
		})
	}
}

func TestX86ApplyWritesBytes(t *testing.T) {
	t.Run("fs becomes gs", func(t *testing.T) {
		block := []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00}
		patched, unsupported := x86CheckApply(t, block, nil, nil)
		want := []byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00}
		if !bytes.Equal(patched, want) || unsupported != 0 {
			t.Errorf("got % x (unsupported %d), want % x (unsupported 0)", patched, unsupported, want)
		}
	})
	t.Run("gs becomes ud2", func(t *testing.T) {
		block := []byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00}
		patched, unsupported := x86CheckApply(t, block, nil, nil)
		want := []byte{0x0f, 0x0b, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00}
		if !bytes.Equal(patched, want) || unsupported != 1 {
			t.Errorf("got % x (unsupported %d), want % x (unsupported 1)", patched, unsupported, want)
		}
	})
	t.Run("gs in the last block byte becomes int3", func(t *testing.T) {
		block := []byte{0x90, 0x65}
		after := []byte{0x48, 0x8b, 0x00}
		want := []x86Edit{{Offset: 1, Kind: x86EditUnsupportedGS, Len: 4}}
		if got := x86Edits(block, nil, after); !reflect.DeepEqual(got, want) {
			t.Fatalf("x86Edits() = %+v, want %+v", got, want)
		}
		patched, unsupported := x86CheckApply(t, block, nil, after)
		if !bytes.Equal(patched, []byte{0x90, 0xcc}) || unsupported != 1 {
			t.Errorf("got % x (unsupported %d), want 90 cc (unsupported 1)", patched, unsupported)
		}
	})
	t.Run("gs in the second last block byte becomes ud2", func(t *testing.T) {
		block := []byte{0x90, 0x65, 0x8b}
		after := []byte{0x00}
		patched, unsupported := x86CheckApply(t, block, nil, after)
		if !bytes.Equal(patched, []byte{0x90, 0x0f, 0x0b}) || unsupported != 1 {
			t.Errorf("got % x (unsupported %d), want 90 0f 0b (unsupported 1)", patched, unsupported)
		}
	})
}

func TestX86EditsBlockBoundaries(t *testing.T) {
	load := []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00}

	t.Run("instruction ends in after", func(t *testing.T) {
		block := joinBytes(bytes.Repeat([]byte{0x90}, 10), load[:7])
		after := load[7:]
		want := []x86Edit{{Offset: 10, Kind: x86EditFSToGS, Len: 9}}
		if got := x86Edits(block, nil, after); !reflect.DeepEqual(got, want) {
			t.Errorf("x86Edits() = %+v, want %+v", got, want)
		}
		x86CheckApply(t, block, nil, after)
	})

	t.Run("instruction cut off without after", func(t *testing.T) {
		block := joinBytes(bytes.Repeat([]byte{0x90}, 10), load[:7])
		if got := x86Edits(block, nil, nil); len(got) != 0 {
			t.Errorf("x86Edits() = %+v, want none", got)
		}
	})

	t.Run("fs prefix byte lies in the next block", func(t *testing.T) {
		first := []byte{0x90, 0x66}
		second := joinBytes([]byte{0x64, 0x8b, 0x04, 0x25}, make([]byte, 4))
		if got := x86Edits(first, nil, second); len(got) != 0 {
			t.Errorf("first block: x86Edits() = %+v, want none", got)
		}
		want := []x86Edit{{Offset: 0, Kind: x86EditFSToGS, Len: 9}}
		if got := x86Edits(second, first, nil); !reflect.DeepEqual(got, want) {
			t.Errorf("second block: x86Edits() = %+v, want %+v", got, want)
		}
		x86CheckApply(t, second, first, nil)
	})

	t.Run("block starts inside an immediate", func(t *testing.T) {
		// "48 b8" opens a movabs. Its eight immediate bytes look like a load
		// and begin the block. The next real load follows the immediate.
		fake := []byte{0x64, 0x48, 0x8b, 0x00, 0x64, 0x48, 0x8b, 0x00}
		block := joinBytes(fake, []byte{0x90}, load)
		before := []byte{0x90, 0x48, 0xb8}

		want := []x86Edit{{Offset: 9, Kind: x86EditFSToGS, Len: 9}}
		if got := x86Edits(block, before, nil); !reflect.DeepEqual(got, want) {
			t.Errorf("with before: x86Edits() = %+v, want %+v", got, want)
		}
		x86CheckApply(t, block, before, nil)

		// Without the bytes before the block, the decoder reads the immediate
		// as code. This is the known limit of linear decoding.
		wantBlind := []x86Edit{
			{Offset: 0, Kind: x86EditFSToGS, Len: 4},
			{Offset: 4, Kind: x86EditFSToGS, Len: 4},
			{Offset: 9, Kind: x86EditFSToGS, Len: 9},
		}
		if got := x86Edits(block, nil, nil); !reflect.DeepEqual(got, wantBlind) {
			t.Errorf("without before: x86Edits() = %+v, want %+v", got, wantBlind)
		}
	})

	t.Run("empty inputs", func(t *testing.T) {
		if got := x86Edits(nil, nil, nil); len(got) != 0 {
			t.Errorf("x86Edits(nil, nil, nil) = %+v, want none", got)
		}
		if got := x86Edits([]byte{}, []byte{0x64}, []byte{0x8b}); len(got) != 0 {
			t.Errorf("x86Edits(empty) = %+v, want none", got)
		}
		if n := x86Apply(nil, nil); n != 0 {
			t.Errorf("x86Apply(nil, nil) = %d, want 0", n)
		}
	})
}

func TestX86EditsDegenerateBlocks(t *testing.T) {
	const pageSize = 4096
	for _, tc := range []struct {
		name  string
		block []byte
	}{
		{"all zero", make([]byte, pageSize)},
		{"all 0x64", bytes.Repeat([]byte{0x64}, pageSize)},
		{"all 0x65", bytes.Repeat([]byte{0x65}, pageSize)},
		{"all 0x0f", bytes.Repeat([]byte{0x0f}, pageSize)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, pageSize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := bytes.Repeat(tc.block[:1], x86MaxBefore)
			after := bytes.Repeat(tc.block[:1], x86MaxAfter)
			edits := x86Edits(tc.block, before, after)
			patched := bytes.Clone(tc.block)
			x86Apply(patched, edits)
			if tc.name == "all zero" && len(edits) != 0 {
				t.Errorf("x86Edits() returned %d edits for zero bytes, want 0", len(edits))
			}
			for _, e := range edits {
				if e.Offset < 0 || e.Offset >= pageSize || e.Len <= 0 {
					t.Fatalf("edit %+v lies outside the block", e)
				}
			}
		})
	}
}

func TestX86EditsCompiledFunction(t *testing.T) {
	code := x86CompiledFunction
	var got []int
	for _, e := range x86Edits(code, nil, nil) {
		if e.Kind != x86EditFSToGS {
			t.Fatalf("unexpected edit %+v", e)
		}
		if code[e.Offset] != 0x64 {
			t.Fatalf("edit %+v does not point to a 0x64 byte", e)
		}
		got = append(got, e.Offset)
	}
	if !reflect.DeepEqual(got, x86CompiledFSOffsets) {
		t.Errorf("FS offsets = %v, want %v", got, x86CompiledFSOffsets)
	}

	patched, unsupported := x86CheckApply(t, code, nil, nil)
	if unsupported != 0 {
		t.Errorf("unsupported = %d, want 0", unsupported)
	}
	diff := 0
	for i := range code {
		if code[i] != patched[i] {
			diff++
			if code[i] != 0x64 || patched[i] != 0x65 {
				t.Errorf("byte %d changed from %#x to %#x", i, code[i], patched[i])
			}
		}
	}
	if diff != len(x86CompiledFSOffsets) {
		t.Errorf("%d bytes changed, want %d", diff, len(x86CompiledFSOffsets))
	}
}

// TestX86EditsResynchronize starts the decoder at every offset from 0 to 16 of
// a real function. Decoding resynchronizes after at most one wrong
// instruction, so every FS prefix behind the second true instruction
// boundary MUST appear in the result.
func TestX86EditsResynchronize(t *testing.T) {
	code := x86CompiledFunction
	trueStarts, _ := x86Starts(code)

	for start := 0; start <= 16; start++ {
		var firstTrue int
		for i, s := range trueStarts {
			if s >= start {
				firstTrue = i
				break
			}
		}
		// The first partial instruction and one more instruction can diverge.
		syncPoint := trueStarts[firstTrue+1]

		var want []int
		for _, off := range x86CompiledFSOffsets {
			if off >= syncPoint {
				want = append(want, off-start)
			}
		}
		var got []int
		for _, e := range x86Edits(code[start:], nil, nil) {
			if e.Offset+start >= syncPoint {
				got = append(got, e.Offset)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("start %d: FS offsets behind %d = %v, want %v", start, syncPoint, got, want)
		}
	}
}

// TestX86EditsResynchronizeWithBefore splits the function into blocks with
// the before and after bytes that the engine passes. Every FS prefix MUST
// receive exactly one edit across all blocks.
func TestX86EditsResynchronizeWithBefore(t *testing.T) {
	code := x86CompiledFunction
	for _, blockSize := range []int{16, 50, 97, 128} {
		var got []int
		for base := 0; base < len(code); base += blockSize {
			end := min(base+blockSize, len(code))
			beforeStart := max(base-x86MaxBefore, 0)
			afterEnd := min(end+x86MaxAfter, len(code))
			for _, e := range x86Edits(code[base:end], code[beforeStart:base], code[end:afterEnd]) {
				got = append(got, base+e.Offset)
			}
		}
		if !reflect.DeepEqual(got, x86CompiledFSOffsets) {
			t.Errorf("block size %d: FS offsets = %v, want %v", blockSize, got, x86CompiledFSOffsets)
		}
	}
}

func TestX86EditsAreDeterministic(t *testing.T) {
	first := x86Edits(x86CompiledFunction, nil, nil)
	for i := 0; i < 3; i++ {
		if got := x86Edits(x86CompiledFunction, nil, nil); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d returned %+v, want %+v", i, got, first)
		}
	}
}
