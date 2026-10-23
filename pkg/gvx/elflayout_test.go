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

package gvx

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

const (
	pfX = 1
	pfW = 2
	pfR = 4

	typeExec = 2
	typeDyn  = 3
)

type testSegment struct {
	flags  uint32
	offset uint64
	vaddr  uint64
	memsz  uint64
}

// buildTestELF returns an ELF64 header with one PT_LOAD program header for
// each segment, in the given order.
func buildTestELF(fileType uint16, segments ...testSegment) []byte {
	b := make([]byte, elfHeaderSize+elfProgHdrSize*len(segments))
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(b[16:], fileType)
	binary.LittleEndian.PutUint64(b[32:], elfHeaderSize)
	binary.LittleEndian.PutUint16(b[52:], elfHeaderSize)
	binary.LittleEndian.PutUint16(b[54:], elfProgHdrSize)
	binary.LittleEndian.PutUint16(b[56:], uint16(len(segments)))
	for i, seg := range segments {
		ph := b[elfHeaderSize+i*elfProgHdrSize:]
		binary.LittleEndian.PutUint32(ph[0:], elfProgLoad)
		binary.LittleEndian.PutUint32(ph[4:], seg.flags)
		binary.LittleEndian.PutUint64(ph[8:], seg.offset)
		binary.LittleEndian.PutUint64(ph[16:], seg.vaddr)
		binary.LittleEndian.PutUint64(ph[32:], seg.memsz)
		binary.LittleEndian.PutUint64(ph[40:], seg.memsz)
	}
	return b
}

func TestELFLayoutProblemAcceptsLayoutsThatMap(t *testing.T) {
	for _, tc := range []struct {
		name     string
		file     []byte
		pageSize uint64
	}{
		{"linker pads to 64KB", buildTestELF(typeExec,
			testSegment{pfR | pfX, 0, 0x10000, 0x20000},
			testSegment{pfR, 0x20000, 0x30000, 0x8000},
			testSegment{pfR | pfW, 0x30000, 0x40000, 0x9000}), 16384},
		{"position-independent executable", buildTestELF(typeDyn,
			testSegment{pfR | pfX, 0, 0, 0x4000},
			testSegment{pfR | pfW, 0x4000, 0x14000, 0x1000}), 16384},
		{"two segments with the same permissions share a page", buildTestELF(typeExec,
			testSegment{pfR, 0, 0x400000, 0x1200},
			testSegment{pfR, 0x1300, 0x401300, 0x100}), 16384},
		{"text and data share a page, which the loader merges", buildTestELF(typeExec,
			testSegment{pfR | pfX, 0, 0x400000, 0x1200},
			testSegment{pfR | pfW, 0x2100, 0x402100, 0x100}), 16384},
		{"the table lists the higher segment first", buildTestELF(typeExec,
			testSegment{pfR | pfW, 0x2100, 0x402100, 0x100},
			testSegment{pfR | pfX, 0, 0x400000, 0x1200}), 16384},
		{"a 4KB layout with 4KB pages", buildTestELF(typeExec,
			testSegment{pfR | pfX, 0, 0x400000, 0x1000},
			testSegment{pfR | pfW, 0x1f40, 0x412f40, 0x100}), 4096},
		{"a segment with no memory size", buildTestELF(typeExec,
			testSegment{pfR | pfX, 0, 0x400000, 0x1200},
			testSegment{pfR | pfW, 0x2100, 0x402100, 0}), 16384},
		{"not ELF", []byte("#!/bin/sh\necho hi\n"), 16384},
		{"a prefix that cuts off the program headers", buildTestELF(typeExec,
			testSegment{pfR | pfX, 0, 0x400000, 0x1000})[:40], 16384},
	} {
		if problem := elfLayoutProblem(tc.file, tc.pageSize); problem != "" {
			t.Errorf("%s: problem %q, want none", tc.name, problem)
		}
	}
}

func TestELFLayoutProblemNamesTheSegment(t *testing.T) {
	for _, tc := range []struct {
		name string
		file []byte
		want []string
	}{
		{"segment is not congruent modulo the page size", buildTestELF(typeExec,
			testSegment{pfR | pfX, 0, 0x400000, 0x1000},
			testSegment{pfR | pfW, 0x1f40, 0x412f40, 0x100}),
			[]string{"program header 1", "vaddr 0x412f40", "offset 0x1f40", "not congruent", "16384-byte"}},
	} {
		problem := elfLayoutProblem(tc.file, 16384)
		for _, want := range tc.want {
			if !strings.Contains(problem, want) {
				t.Errorf("%s: problem %q does not contain %q", tc.name, problem, want)
			}
		}
	}
}

func TestCheckELFLayout(t *testing.T) {
	bad := buildTestELF(typeExec,
		testSegment{pfR | pfX, 0, 0x400000, 0x1000},
		testSegment{pfR | pfW, 0x1f40, 0x412f40, 0x100})
	readOf := func(file []byte, err error) func(string, int) ([]byte, error) {
		return func(path string, maxBytes int) ([]byte, error) { return file, err }
	}

	t.Run("a layout that the page size cannot map", func(t *testing.T) {
		err := (&Sandbox{}).checkELFLayout(readOf(bad, nil), "/bin/app", 16384)
		if !errors.Is(err, ErrUnsupportedELFLayout) {
			t.Fatalf("error = %v, want ErrUnsupportedELFLayout", err)
		}
		for _, want := range []string{`"/bin/app"`, "program header 1", "-z max-page-size=16384", "4KB guest pages"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		}
	})
	t.Run("the disable switch", func(t *testing.T) {
		s := &Sandbox{cfg: Config{DisableELFLayoutCheck: true}}
		if err := s.checkELFLayout(readOf(bad, nil), "/bin/app", 16384); err != nil {
			t.Errorf("error = %v, want none", err)
		}
	})
	t.Run("a build with 4KB pages", func(t *testing.T) {
		if err := (&Sandbox{}).checkELFLayout(readOf(bad, nil), "/bin/app", 4096); err != nil {
			t.Errorf("error = %v, want none", err)
		}
	})
	t.Run("a file that the reader cannot return", func(t *testing.T) {
		for name, read := range map[string]func(string, int) ([]byte, error){
			"missing": readOf(nil, nil),
			"error":   readOf(nil, errors.New("read failed")),
		} {
			if err := (&Sandbox{}).checkELFLayout(read, "/bin/app", 16384); err != nil {
				t.Errorf("%s: error = %v, want none", name, err)
			}
		}
	})
}
