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

//go:build darwin

package iouringfs

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// Setup returns ENOSYS on macOS hosts so Linux guests fall back to epoll/poll.
func Setup(_ uint32, _ *linux.IOUringParams) (int, error) {
	return -1, linuxerr.ENOSYS
}

// Enter returns ENOSYS on macOS hosts.
func Enter(_ int, _ uint32, _ uint32, _ uint32) (int, error) {
	return -1, linuxerr.ENOSYS
}

// Register returns ENOSYS on macOS hosts.
func Register(_ int, _ uint32, _ uintptr, _ uint32) error {
	return linuxerr.ENOSYS
}
