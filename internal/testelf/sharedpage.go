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

package testelf

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

const (
	// SharedPageOK is the text that a shared-page guest writes when every check
	// passes.
	SharedPageOK = "shared-page-ok\n"

	// The exit codes of a shared-page guest that fails a check.
	SharedPageExitPlainStore     = 2
	SharedPageExitExclusiveStore = 3
	SharedPageExitPairStore      = 4

	sharedCodeOffset = 0x100
	sharedDataSplit  = 0x2000
	sharedImageSize  = 0x3000
	sharedMsgOffset  = 0xa0
)

// sharedPageProgram is the code of a shared-page guest for arm64. The code
// reaches its data through `adr`, so it needs no relocation. The data lies
// 0x2000 bytes behind the first instruction. The program runs three checks.
// A plain `str` and `ldr` pair, 1000 rounds of `ldxr` and `stxr` on one word,
// and an `stp` and `ldp` pair. It writes SharedPageOK and exits with 0, or it
// exits with the code of the first failed check.
var sharedPageProgram = [...]uint32{
	0x10010009, // adr   x9, data
	0x52824681, // mov   w1, #0x1234
	0xb9000121, // str   w1, [x9]
	0xb9400122, // ldr   w2, [x9]
	0x6b02003f, // cmp   w1, w2
	0x54000381, // b.ne  fail2
	0xb900093f, // str   wzr, [x9, #8]
	0x9100212a, // add   x10, x9, #8
	0x52807d03, // mov   w3, #1000
	0x885f7d44, // loop: ldxr  w4, [x10]
	0x11000484, // add   w4, w4, #1
	0x88057d44, // stxr  w5, w4, [x10]
	0x35ffffa5, // cbnz  w5, loop
	0x71000463, // subs  w3, w3, #1
	0x54ffff61, // b.ne  loop
	0xb9400144, // ldr   w4, [x10]
	0x710fa09f, // cmp   w4, #1000
	0x54000241, // b.ne  fail3
	0x9100412b, // add   x11, x9, #16
	0xa9001161, // stp   x1, x4, [x11]
	0xa9401d66, // ldp   x6, x7, [x11]
	0xeb0100df, // cmp   x6, x1
	0x540001e1, // b.ne  fail4
	0xeb0400ff, // cmp   x7, x4
	0x540001a1, // b.ne  fail4
	0xd2800020, // mov   x0, #1
	0x100001c1, // adr   x1, msg
	0xd28001e2, // mov   x2, #15
	0xd2800808, // mov   x8, #64 (write)
	0xd4000001, // svc   #0
	0xd2800000, // mov   x0, #0
	0xd2800bc8, // mov   x8, #94 (exit_group)
	0xd4000001, // svc   #0
	0xd2800040, // fail2: mov x0, #2
	0x14000004, // b     done
	0xd2800060, // fail3: mov x0, #3
	0x14000002, // b     done
	0xd2800080, // fail4: mov x0, #4
	0xd2800bc8, // done: mov x8, #94
	0xd4000001, // svc   #0
}

// The message must start right behind the last instruction.
var _ [0]struct{} = [sharedMsgOffset - len(sharedPageProgram)*4]struct{}{}

// BuildSharedPageGuestELF64 synthesizes a static arm64 Linux ELF64 executable
// that links at baseVA. Its code and its data share one 16KB host page. A
// segment with the flags R and X holds the code, and a segment with the flags
// R and W starts 8KB behind it. The guest stores to data in a page that also
// holds code. It writes SharedPageOK and exits with 0 when plain stores,
// exclusive stores, and pair stores read back. The data starts at offset
// 0x2100 from baseVA. Every segment is congruent modulo 16KB when baseVA is a
// multiple of 16KB, which this function requires. Use a baseVA that the
// execution backend allows.
func BuildSharedPageGuestELF64(baseVA uint64) ([]byte, error) {
	if baseVA%(16<<10) != 0 {
		return nil, fmt.Errorf("testelf: baseVA %#x is not aligned to 16KB", baseVA)
	}
	if baseVA >= 1<<48 {
		return nil, fmt.Errorf("testelf: baseVA %#x is above the 48-bit address space", baseVA)
	}
	const (
		elfHeaderSize = 64
		phdrSize      = 56
	)
	img := make([]byte, sharedImageSize)
	copy(img[0:4], []byte{0x7f, 'E', 'L', 'F'})
	img[4] = byte(elf.ELFCLASS64)
	img[5] = byte(elf.ELFDATA2LSB)
	img[6] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(img[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(img[18:20], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(img[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(img[24:32], baseVA+sharedCodeOffset)
	binary.LittleEndian.PutUint64(img[32:40], elfHeaderSize)
	binary.LittleEndian.PutUint16(img[52:54], elfHeaderSize)
	binary.LittleEndian.PutUint16(img[54:56], phdrSize)

	segs := [...]struct {
		flags       uint32
		offset, len uint64
	}{
		{uint32(elf.PF_R | elf.PF_X), 0, sharedDataSplit},
		{uint32(elf.PF_R | elf.PF_W), sharedDataSplit, sharedImageSize - sharedDataSplit},
	}
	binary.LittleEndian.PutUint16(img[56:58], uint16(len(segs)))
	for i, seg := range segs {
		ph := img[elfHeaderSize+i*phdrSize:][:phdrSize]
		binary.LittleEndian.PutUint32(ph[0:4], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(ph[4:8], seg.flags)
		binary.LittleEndian.PutUint64(ph[8:16], seg.offset)
		binary.LittleEndian.PutUint64(ph[16:24], baseVA+seg.offset)
		binary.LittleEndian.PutUint64(ph[24:32], baseVA+seg.offset)
		binary.LittleEndian.PutUint64(ph[32:40], seg.len)
		binary.LittleEndian.PutUint64(ph[40:48], seg.len)
		binary.LittleEndian.PutUint64(ph[48:56], 4096)
	}
	copy(img[sharedCodeOffset:], encodeARM64Words(sharedPageProgram[:]))
	copy(img[sharedCodeOffset+sharedMsgOffset:], SharedPageOK)
	return img, nil
}
