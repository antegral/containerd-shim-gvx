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

//go:build darwin && arm64 && pagesize_16k

package systrap

import (
	"encoding/binary"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
)

// The guests of the zone tests link where a fixed-address executable links: the
// code at 0x400000 and the data at 0x500000. The stub holds them at the bias.
const (
	zoneCode = 0x400000
	zoneData = 0x500000
)

var (
	readExec  = hostarch.AccessType{Read: true, Execute: true}
	readWrite = hostarch.ReadWrite
)

// newZonePlatform starts a platform in zone mode. It skips the test when the
// guest address range of the host cannot hold the zone.
func newZonePlatform(t testing.TB) *Platform {
	t.Helper()
	t.Setenv(ZoneEnv, "1")
	p, err := New()
	if err != nil {
		if strings.Contains(err.Error(), "cannot hold the zone") {
			t.Skipf("zone mode is unavailable on this host: %v", err)
		}
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return p
}

func newZoneRig(t testing.TB) *rig {
	t.Helper()
	return newRig(t, newZonePlatform(t))
}

// zoneProgram maps the guest code at zoneCode, a stack above the biased zone,
// and starts the thread at the guest address of the entry.
func (r *rig) zoneProgram(entry uint64, words ...uint32) {
	r.t.Helper()
	r.mapPage(zoneCode, readExec, words...)
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(uintptr(entry))
	r.ac.SetStack(stackVA + blockSize - 0x100)
}

func put64(mem []byte, off int, v uint64) { binary.LittleEndian.PutUint64(mem[off:], v) }
func get64(mem []byte, off int) uint64    { return binary.LittleEndian.Uint64(mem[off:]) }

// accessProgram comes from access.s of the zone tests. It loads and stores
// through guest pointers of the zone in every form that a slot covers.
var accessProgram = []uint32{
	0xd2800001, 0xf2a00a01, 0xf9400020, 0xd297dde2, 0xf2bbd5a2, 0xf9000422, 0xf9400423, 0x91004025,
	0xf94000a5, 0x91006026, 0xf90000c6, 0xaa1f03e7, 0xaa0103e9, 0xf86968ea, 0xaa0103e7, 0xd2800109,
	0xf86968eb, 0xa942342c, 0xa9030c22, 0x9101002e, 0xf84085cf, 0x91014034, 0xc85f7e95, 0x910006b5,
	0xc8167e95, 0x35ffffb6, 0xd2800128, 0xd4000001,
}

func TestZoneLoadsAndStoresThroughGuestPointers(t *testing.T) {
	r := newZoneRig(t)
	r.zoneProgram(zoneCode, accessProgram...)
	mem := r.mapPage(zoneData, readWrite)
	put64(mem, 0, 0x1122334455667788)
	put64(mem, 16, 0x7000_0000_1234) // a pointer outside the zone, with the bias bit set
	put64(mem, 32, 0xaaaa)
	put64(mem, 40, 0xbbbb)
	put64(mem, 64, 0x77)
	put64(mem, 80, 41)

	si, _, err := r.run()
	mustSyscall(t, si, err, 9, r.ac)
	x := &r.regs().Regs
	for _, tc := range []struct {
		what      string
		got, want uint64
	}{
		{"x0, a load", x[0], 0x1122334455667788},
		{"x3, a store and a load", x[3], 0xdeadbeef},
		{"x5, a load that overwrites its base", x[5], 0x7000_0000_1234},
		{"x10, a load with the base 0 and the pointer in the index", x[10], 0x1122334455667788},
		{"x11, a load with the pointer in the base", x[11], 0xdeadbeef},
		{"x12, the first of a pair load", x[12], 0xaaaa},
		{"x13, the second of a pair load", x[13], 0xbbbb},
		{"x15, a post-index load", x[15], 0x77},
		{"x1, the base after the accesses", x[1], zoneData},
		{"x6, the stored base after the accesses", x[6], zoneData + 24},
		{"x14, the post-index base", x[14], zoneData + 72},
		{"x20, the exclusive base", x[20], zoneData + 80},
		{"the stored base register", get64(mem, 24), zoneData + 24},
		{"the first stored register of a pair", get64(mem, 48), 0xdeadbeef},
		{"the second stored register of a pair", get64(mem, 56), 0xdeadbeef},
		{"the word of the exclusive loop", get64(mem, 80), 42},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, want %#x", tc.what, tc.got, tc.want)
		}
	}
}

func TestZoneAdrAndAdrpYieldGuestAddresses(t *testing.T) {
	r := newZoneRig(t)
	r.zoneProgram(zoneCode, 0x90000800, 0x91048000, 0x10000201, 0xd2800128, 0xd4000001)
	si, _, err := r.run()
	mustSyscall(t, si, err, 9, r.ac)
	x := &r.regs().Regs
	if x[0] != zoneData+0x120 {
		t.Errorf("adrp and add = %#x, want the guest address %#x", x[0], zoneData+0x120)
	}
	if want := uint64(zoneCode + 8 + 0x40); x[1] != want {
		t.Errorf("adr = %#x, want the guest address %#x", x[1], want)
	}
}

func TestZoneIndirectBranchesTakeGuestPointers(t *testing.T) {
	r := newZoneRig(t)
	prog := make([]uint32, 0x30)
	copy(prog, []uint32{0xd2800001, 0xf2a00a01, 0xf9400028, 0xd63f0100, 0x91000400, 0xf9400429, 0xd61f0120})
	prog[0x80/4], prog[0x84/4] = 0xd2800c60, 0xd65f03c0
	prog[0xa0/4], prog[0xa4/4], prog[0xa8/4] = 0xd28000aa, 0xd2800128, 0xd4000001
	r.zoneProgram(zoneCode, prog...)
	mem := r.mapPage(zoneData, readWrite)
	put64(mem, 0, zoneCode+0x80)
	put64(mem, 8, zoneCode+0xa0)
	si, _, err := r.run()
	mustSyscall(t, si, err, 9, r.ac)
	x := &r.regs().Regs
	if x[0] != 100 || x[10] != 5 {
		t.Errorf("x0, x10 = %d, %d, want 100, 5: blr must call, ret must return, and br must jump", x[0], x[10])
	}
}

func TestZoneFaultsReportGuestAddresses(t *testing.T) {
	t.Run("an unmapped guest address of the zone", func(t *testing.T) {
		r := newZoneRig(t)
		r.zoneProgram(zoneCode, append(loadAddr(1, 0x600000), ldrX(0, 1))...)
		si, at, err := r.run()
		wantSignal(t, si, at, err, linux.SIGSEGV, 1, 0x600000, hostarch.Read)
	})
	t.Run("a null pointer through a patched site", func(t *testing.T) {
		// The first pass patches the load, because its pointer lies in the zone.
		// The second pass loads through the null pointer inside the slot. The
		// Sentry must report the guest address and the guest register.
		r := newZoneRig(t)
		r.zoneProgram(zoneCode, 0xd29fff01, 0xf2a009e1, 0xd2800042, 0xf9400420, 0xaa1f03e1, 0xf1000442, 0x54ffffa1, 0xd2800128, 0xd4000001)
		r.mapPage(zoneData, readWrite)
		si, at, err := r.run()
		wantSignal(t, si, at, err, linux.SIGSEGV, 1, 8, hostarch.Read)
		if got := r.regs().Regs[1]; got != 0 {
			t.Errorf("x1 = %#x after the fault, want the guest value 0", got)
		}
		if got, want := r.regs().Pc, uint64(zoneBias+zoneCode+12); got != want {
			t.Errorf("pc = %#x, want the site %#x", got, want)
		}
	})
}

func TestZoneAccessThroughAnX18SlotBody(t *testing.T) {
	// An instruction that names x18 runs in an x18 slot, because the kernel of
	// macOS zeroes the real x18. The load through a guest pointer of the zone
	// then happens inside the slot, and the Sentry must patch that word.
	r := newZoneRig(t)
	r.zoneProgram(zoneCode, append(loadAddr(1, zoneData),
		0xf9400032, // ldr x18, [x1]
		0xaa1203e2, // mov x2, x18
		movz(8, 9), insnSVC0)...)
	mem := r.mapPage(zoneData, readWrite)
	put64(mem, 0, 0x5eed_f00d)
	si, _, err := r.run()
	mustSyscall(t, si, err, 9, r.ac)
	if got := r.regs().Regs[2]; got != 0x5eed_f00d {
		t.Errorf("x2 = %#x, want the value that the load through x18 read", got)
	}
	if got := r.regs().Regs[1]; got != zoneData {
		t.Errorf("x1 = %#x after the access, want the guest address %#x", got, zoneData)
	}
}

func TestZoneCacheMaintenanceThroughGuestPointers(t *testing.T) {
	// memset of musl zeroes a large block with dc zva, and a code generator
	// cleans the data cache and invalidates the instruction cache by address.
	// Each instruction names a guest pointer of the zone, so each faults at
	// its first run and needs a slot.
	r := newZoneRig(t)
	r.zoneProgram(zoneCode, append(loadAddr(1, zoneData+0x400),
		0xd50b7421, // dc zva, x1
		0xd50b7b21, // dc cvau, x1
		0xd50b7521, // ic ivau, x1
		0xd5033b9f, // dsb ish
		0xd5033fdf, // isb
		movz(8, 9), insnSVC0)...)
	mem := r.mapPage(zoneData, readWrite)
	for i := range mem {
		mem[i] = 0xff
	}
	si, _, err := r.run()
	mustSyscall(t, si, err, 9, r.ac)
	if got := get64(mem, 0x400); got != 0 {
		t.Errorf("word at the zeroed address = %#x, want 0", got)
	}
	if got := get64(mem, 0x2000); got != ^uint64(0) {
		t.Errorf("word far from the zeroed block = %#x, want it unchanged", got)
	}
	if got := r.regs().Regs[1]; got != zoneData+0x400 {
		t.Errorf("x1 = %#x after the instructions, want the guest address %#x", got, zoneData+0x400)
	}
}

func TestZoneRegisterOffsetAcceptsANegativeIndex(t *testing.T) {
	// A negative index sets the bias bit, like a pointer outside the zone does.
	// The slot must still treat the base as the pointer of the zone. The
	// dynamic linker of musl runs ldr x0, [x0, x2] with a negative x2 when it
	// walks back from a pointer to the header of a chunk.
	r := newZoneRig(t)
	r.zoneProgram(zoneCode, append(loadAddr(0, zoneData+0x40),
		0x928001e2, // mov x2, #-16
		0xf8626803, // ldr x3, [x0, x2]
		0xf8626800, // ldr x0, [x0, x2]
		movz(8, 9), insnSVC0)...)
	mem := r.mapPage(zoneData, readWrite)
	put64(mem, 0x30, 0x1111)
	put64(mem, 0x40, 0x2222)
	si, _, err := r.run()
	mustSyscall(t, si, err, 9, r.ac)
	x := &r.regs().Regs
	if x[3] != 0x1111 || x[0] != 0x1111 {
		t.Errorf("x3, x0 = %#x, %#x, want 0x1111 from the address 16 bytes below the base", x[3], x[0])
	}
}

func TestUnmapAcrossTheHoleKeepsTheBiasedZone(t *testing.T) {
	// The memory manager unmaps a range that starts in the zone and ends near
	// the top of the address range. The biased zone lies inside that range as
	// the stub sees it, and the range must not remove it.
	p := newZonePlatform(t)
	got := p.stubRanges(0x6144000, 0x7ffe_ec2c_0000)
	want := [][2]uint64{
		{0x6144000 + zoneBias, zoneLimit + zoneBias},
		{zoneBias + zoneLimit, 0x7ffe_ec2c_0000},
	}
	if len(got) != len(want) {
		t.Fatalf("stubRanges = %#x, want %#x", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("range %d = %#x, want %#x", i, got[i], want[i])
		}
	}
	for _, r := range got[1:] {
		if r[0] < zoneBias+zoneLimit {
			t.Errorf("range %#x reaches into the hole that holds the biased zone", r)
		}
	}
}
