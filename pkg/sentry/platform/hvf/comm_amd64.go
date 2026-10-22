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

// CommPage is the page that the Ring-0 stub and the Sentry share.
type CommPage = x86CommPage

// maxUserAddress is the end of the user half of the address space: 48 bits of
// the TTBR0_EL1 range on ARM64, and the lower canonical half of 4-level paging on x86.
const maxUserAddress = 1 << 47
