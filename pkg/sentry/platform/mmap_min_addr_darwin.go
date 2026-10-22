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

package platform

import "z.gfire.dev/gvx/pkg/hostarch"

const defaultMMapMinAddr = 0x10000

// SystemMMapMinAddr returns the minimum guest user virtual address on macOS.
func SystemMMapMinAddr() hostarch.Addr {
	return hostarch.Addr(defaultMMapMinAddr)
}

// MMapMinAddr implements MinUserAddress using the default minimum guest address.
type MMapMinAddr struct{}

// MinUserAddress implements platform.MinUserAddress.
func (*MMapMinAddr) MinUserAddress() hostarch.Addr {
	return SystemMMapMinAddr()
}
