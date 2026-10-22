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

// CommPage is the 4KB page that the EL1 stub and the Sentry share. The stub
// writes it on every guest exit and reads it on every guest entry. Field
// offsets are part of the stub encoding: stub_arm64.go derives them from this
// declaration.
type CommPage struct {
	Regs      [31]uint64    // 0: X0..X30.
	SP        uint64        // 248: SP_EL0.
	PC        uint64        // 256: ELR_EL1.
	Pstate    uint64        // 264: SPSR_EL1.
	TLS       uint64        // 272: TPIDR_EL0.
	FaultAddr uint64        // 280: FAR_EL1.
	ESR       uint64        // 288: ESR_EL1.
	Vector    uint64        // 296: vector slot of the exception.
	Flags     uint64        // 304: host-to-guest flush flags.
	_         uint64        // 312.
	VRegs     [32][2]uint64 // 320: V0..V31 (Q0..Q31).
	FPSR      uint64        // 832.
	FPCR      uint64        // 840.
	_         [3248]byte    // 848: pads the page to 4096 bytes.
}

// maxUserAddress is the end of the user half of the address space: 48 bits of
// the TTBR0_EL1 range on ARM64, and the lower canonical half of 4-level paging on x86.
const maxUserAddress = 1 << 48
