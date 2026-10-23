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

import "encoding/binary"

// elfProbeBytes is the size of the file prefix that the executable checks
// read. The program headers of an executable lie right behind the ELF header.
const elfProbeBytes = 16 << 10

const (
	elfHeaderSize  = 64
	elfTypeExec    = 2
	elfProgLoad    = 1
	elfProgHdrSize = 56
)

// loadSegment is a PT_LOAD program header that maps memory.
type loadSegment struct {
	// index is the position of the segment in the program header table.
	index  int
	flags  uint32
	offset uint64
	vaddr  uint64
	memsz  uint64
}

// parseLoadSegments returns the file type and the PT_LOAD segments of a
// little-endian ELF64 file. A segment with no memory size is left out. It
// returns false for another kind of file and for a prefix that cuts off the
// program header table.
func parseLoadSegments(header []byte) (fileType uint16, segments []loadSegment, ok bool) {
	if len(header) < elfHeaderSize || string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 {
		return 0, nil, false
	}
	phoff := binary.LittleEndian.Uint64(header[32:])
	phentsize := uint64(binary.LittleEndian.Uint16(header[54:]))
	phnum := uint64(binary.LittleEndian.Uint16(header[56:]))
	if phentsize < elfProgHdrSize {
		return 0, nil, false
	}
	for i := range phnum {
		off := phoff + i*phentsize
		if off+elfProgHdrSize > uint64(len(header)) {
			return 0, nil, false
		}
		ph := header[off : off+elfProgHdrSize]
		if binary.LittleEndian.Uint32(ph[0:]) != elfProgLoad || binary.LittleEndian.Uint64(ph[40:]) == 0 {
			continue
		}
		segments = append(segments, loadSegment{
			index:  int(i),
			flags:  binary.LittleEndian.Uint32(ph[4:]),
			offset: binary.LittleEndian.Uint64(ph[8:]),
			vaddr:  binary.LittleEndian.Uint64(ph[16:]),
			memsz:  binary.LittleEndian.Uint64(ph[40:]),
		})
	}
	return binary.LittleEndian.Uint16(header[16:]), segments, true
}
