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

// EL1 system register values that every vCPU receives at creation.

const (
	// mairEL1 defines attribute 0 as normal write-back memory with read and
	// write allocation. Every descriptor of this backend uses attribute 0.
	mairEL1 uint64 = 0xff

	// cpacrEL1 sets FPEN to 0b11: EL0 and EL1 use FP and Advanced SIMD
	// without trapping.
	cpacrEL1 uint64 = 3 << 20

	// cntkctlEL1 sets EL0PCTEN and EL0VCTEN, so guest code reads the physical
	// and virtual counters without a trap.
	cntkctlEL1 uint64 = 3

	// cntvCtlMasked sets CNTV_CTL_EL0.IMASK. The guest never programs the
	// virtual timer, and the mask keeps it from raising an exit.
	cntvCtlMasked uint64 = 2

	// pstateEL1h is EL1 with SP_EL1 selected and DAIF masked.
	pstateEL1h uint64 = 0x3c5

	// pstateModeMask selects the M[4:0] field of PSTATE. EL0t is zero.
	pstateModeMask uint64 = 0x1f

	// pstateUserMask keeps the condition flags N, Z, C and V, which are the
	// only PSTATE bits that Linux user code changes directly.
	pstateUserMask uint64 = 0xf0000000
)

// sctlrEL1 enables the MMU and the caches, and lets EL0 run the instructions
// that glibc and the Go runtime use without a trap to EL1.
const sctlrEL1 uint64 = 0 |
	1<<0 | // M: Stage-1 translation on.
	1<<2 | // C: data caches on.
	1<<3 | // SA: SP alignment check at EL1.
	1<<4 | // SA0: SP alignment check at EL0, as Linux does.
	1<<12 | // I: instruction caches on.
	1<<14 | // DZE: DC ZVA runs at EL0.
	1<<15 | // UCT: CTR_EL0 reads at EL0.
	1<<16 | // nTWI: WFI runs at EL0.
	1<<18 | // nTWE: WFE runs at EL0.
	1<<26 | // UCI: IC IVAU, DC CVAU, DC CIVAC and DC CVAC run at EL0.
	sctlrRes1

// sctlrRes1 holds the bits that are RES1 on cores without the matching
// features, with the values Linux writes.
const sctlrRes1 uint64 = 1<<11 | 1<<20 | 1<<22 | 1<<23 | 1<<28 | 1<<29

// tcrEL1 returns the TCR_EL1 value for 4KB granules, 48-bit input addresses in
// both halves, inner-shareable write-back table walks, top-byte-ignore for
// TTBR0, and an output size of ips (the IPS field encoding). EPD0 and EPD1
// stay clear, so both TTBR0_EL1 and TTBR1_EL1 translate.
func tcrEL1(ips uint64) uint64 {
	const (
		t0sz  = 16
		irgn0 = 1 << 8
		orgn0 = 1 << 10
		sh0   = 3 << 12
		tg0   = 0 << 14 // 4KB.
		t1sz  = 16 << 16
		irgn1 = 1 << 24
		orgn1 = 1 << 26
		sh1   = 3 << 28
		tg1   = 2 << 30 // 4KB: TG1 encodes granules differently from TG0.
		tbi0  = 1 << 37
	)
	return t0sz | irgn0 | orgn0 | sh0 | tg0 | t1sz | irgn1 | orgn1 | sh1 | tg1 | ips<<32 | tbi0
}
