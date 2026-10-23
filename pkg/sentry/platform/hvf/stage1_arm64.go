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

// userUpperStart is the first address of the TTBR1 range. The user tree
// shares the root of the kernel tree for addresses from here up. TTBR0_EL1
// translates every address below it.
const userUpperStart uintptr = 0xffff_0000_0000_0000

// RootIPA returns the guest physical address of the level-0 table for
// TTBR0_EL1. The ASID is zero: the stub flushes the TLB on a table change.
func (s *stage1Tables) RootIPA() uint64 {
	return s.pt.TTBR0_EL1(false, 0)
}

// initPageTables prepares pkg/ring0/pagetables for the first tree.
func initPageTables() {}
