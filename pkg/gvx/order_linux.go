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

//go:build linux

package gvx

import "z.gfire.dev/gvx/pkg/sentry/platform"

// platformAfterLockdown is true on Linux. A Landlock domain lets a thread
// trace only processes that live in the same domain or in a child domain. The
// upstream systrap platform traces its stub processes, so the platform must
// start after the lockdown and fork its first stub inside the domain.
const platformAfterLockdown = true

// lockdownReadPaths lists what the platform reads while it starts under the
// lockdown. The first start reads /proc/self/maps.
func lockdownReadPaths() []string { return []string{"/proc/self"} }

// primeHost caches the facts that the platform reads from files, so the
// lockdown does not need to allow those files. The call reads
// /proc/sys/vm/mmap_min_addr once and keeps the value.
func primeHost() { _ = platform.SystemMMapMinAddr() }
