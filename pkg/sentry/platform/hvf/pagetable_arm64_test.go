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

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
)

func perms(desc uint64) hostarch.AccessType {
	if desc&pteValid == 0 || desc&pteAPEL0 == 0 {
		return hostarch.NoAccess
	}
	return hostarch.AccessType{Read: true, Write: desc&pteAPRO == 0, Execute: desc&pteUXN == 0}
}

func TestMapPageEncodesExactPermissions(t *testing.T) {
	cases := []struct {
		name string
		at   hostarch.AccessType
	}{
		{"read", hostarch.Read},
		{"read write", hostarch.ReadWrite},
		{"read execute", hostarch.AccessType{Read: true, Execute: true}},
		{"read write execute", hostarch.AnyAccess},
		{"execute only", hostarch.Execute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newFakeAllocator()
			pt, err := NewGuestPageTable(a, nil)
			if err != nil {
				t.Fatal(err)
			}
			const va, ipa = 0x7f12_3456_7000, 0x2_0000_5000
			if _, err := pt.MapPage(va, ipa, tc.at); err != nil {
				t.Fatalf("MapPage: %v", err)
			}
			desc, ok := walk(a, pt.tables.root, va)
			if !ok {
				t.Fatal("the walk does not reach a leaf")
			}
			if got := desc & pteAddrMask; got != ipa {
				t.Errorf("output address = %#x, want %#x", got, ipa)
			}
			want := tc.at
			want.Read = true // EL0 cannot execute a page that it cannot read.
			if got := perms(desc); got != want {
				t.Errorf("decoded permissions = %v, want %v", got, want)
			}
			if desc&ptePXN == 0 {
				t.Error("EL1 can execute a user page: PXN is clear")
			}
			if desc&pteNG == 0 {
				t.Error("a user page is global: nG is clear")
			}
			if desc&pteAF == 0 {
				t.Error("the access flag is clear: the first access would fault")
			}
		})
	}
}

func TestMapPageWithoutAccessIsInvalid(t *testing.T) {
	a := newFakeAllocator()
	pt, _ := NewGuestPageTable(a, nil)
	if _, err := pt.MapPage(0x400000, 0x2_0000_0000, hostarch.NoAccess); err != nil {
		t.Fatal(err)
	}
	if desc, _ := walk(a, pt.tables.root, 0x400000); desc != 0 {
		t.Errorf("descriptor = %#x, want an invalid entry", desc)
	}
}

func TestKernelDescriptorsAreGlobalAndEL1Only(t *testing.T) {
	code := kernelLeafDescriptor(0x1_0000_3000, kernelCode)
	data := kernelLeafDescriptor(0x1_0000_4000, kernelData)
	for name, desc := range map[string]uint64{"code": code, "data": data} {
		if desc&pteNG != 0 {
			t.Errorf("%s: nG is set, but kernel mappings must be global", name)
		}
		if desc&pteAPEL0 != 0 {
			t.Errorf("%s: EL0 can access the page", name)
		}
		if desc&pteUXN == 0 {
			t.Errorf("%s: EL0 can execute the page", name)
		}
	}
	if code&ptePXN != 0 || code&pteAPRO == 0 {
		t.Errorf("code page descriptor %#x must be EL1 executable and read-only", code)
	}
	if data&ptePXN == 0 || data&pteAPRO != 0 {
		t.Errorf("data page descriptor %#x must be EL1 read-write and never executable", data)
	}
}
