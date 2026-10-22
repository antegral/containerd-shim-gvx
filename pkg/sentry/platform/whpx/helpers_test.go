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

package whpx

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

var platformASOptions = platform.AddressSpaceOptions{}

// mustHost returns pages of zeroed host memory from the fake backend.
func mustHost(t testing.TB, fb *fakeBackend, pages int) []byte {
	t.Helper()
	mem, err := fb.allocHost(ptSlabSize)
	if err != nil {
		t.Fatal(err)
	}
	return mem[:pages*pageSize]
}

// fakeFile is a memmap.File whose MapInternal returns scripted memory.
type fakeFile struct {
	memmap.File
	blocks    []safemem.Block
	err       error
	lastAT    hostarch.AccessType
	mapCalled int
}

func (f *fakeFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	f.mapCalled++
	f.lastAT = at
	if f.err != nil {
		return safemem.BlockSeq{}, f.err
	}
	return safemem.BlockSeqFromSlice(f.blocks), nil
}

// fakeMM implements the part of platform.MemoryManager that Switch uses.
type fakeMM struct {
	platform.MemoryManager
	as platform.AddressSpace
}

func (m *fakeMM) AddressSpace() platform.AddressSpace { return m.as }

func newTestAS(t testing.TB, p *Platform) *AddressSpace {
	t.Helper()
	as, err := p.NewAddressSpace(platformASOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(as.Release)
	return as.(*AddressSpace)
}
