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

import "z.gfire.dev/gvx/pkg/ring0/pagetables"

// userUpperStart is the first address of the shared kernel subtree. It is
// the first address under PML4 entry 511. A user tree copies that entry from
// the kernel tree, so the Ring-0 image is present under every CR3.
const userUpperStart = uintptr(x86KernelBaseVA)

// RootIPA returns the guest physical address of the PML4 for CR3. The PCID is
// zero, so a CR3 write flushes the TLB.
func (s *stage1Tables) RootIPA() uint64 {
	return s.pt.CR3(false, 0)
}

// initPageTables prepares pkg/ring0/pagetables for the first tree. The
// package builds a five-level layout on a CPU with LA57, and Hypervisor.framework
// guests use four levels.
func initPageTables() {
	pagetables.DisableLA57()
}
