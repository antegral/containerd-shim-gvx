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

//go:build linux && amd64

package gvx

import (
	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/seccomp"
)

// archRejectedRules lists the amd64 calls that arm64 lacks: open, creat, fork,
// and vfork.
func archRejectedRules() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_OPEN:  seccomp.MatchAll{},
		unix.SYS_CREAT: seccomp.MatchAll{},
		unix.SYS_FORK:  seccomp.MatchAll{},
		unix.SYS_VFORK: seccomp.MatchAll{},
	})
}
