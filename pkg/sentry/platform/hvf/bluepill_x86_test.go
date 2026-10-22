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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func emitted(f func(b *x86CodeBuilder)) []byte {
	b := &x86CodeBuilder{page: make([]byte, 64)}
	f(b)
	return b.page[:b.off]
}

// The expected bytes come from assembling the same instructions with clang
// (-target x86_64-apple-macos10.15) and reading them back with otool.
func TestX86EncodersMatchAssembler(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"swapgs", emitted(func(b *x86CodeBuilder) { b.swapgs() }), "0f01f8"},
		{"hlt", emitted(func(b *x86CodeBuilder) { b.hlt() }), "f4"},
		{"iretq", emitted(func(b *x86CodeBuilder) { b.iretq() }), "48cf"},
		{"mov rax to gs:0x10", emitted(func(b *x86CodeBuilder) { b.movToGS(0, 0x10) }), "654889042510000000"},
		{"mov rsp to gs:0x80", emitted(func(b *x86CodeBuilder) { b.movToGS(4, 0x80) }), "654889242580000000"},
		{"mov r15 to gs:0x78", emitted(func(b *x86CodeBuilder) { b.movToGS(15, 0x78) }), "654c893c2578000000"},
		{"mov r8 to gs:0x40", emitted(func(b *x86CodeBuilder) { b.movToGS(8, 0x40) }), "654c89042540000000"},
		{"mov gs:0x88 to rsp", emitted(func(b *x86CodeBuilder) { b.movFromGS(4, 0x88) }), "65488b242588000000"},
		{"mov gs:0x78 to r15", emitted(func(b *x86CodeBuilder) { b.movFromGS(15, 0x78) }), "654c8b3c2578000000"},
		{"push gs:0x80", emitted(func(b *x86CodeBuilder) { b.pushGS(0x80) }), "65ff342580000000"},
		{"push 0x2b", emitted(func(b *x86CodeBuilder) { b.pushImm(0x2b) }), "6a2b"},
		{"push 0x100", emitted(func(b *x86CodeBuilder) { b.pushImm(0x100) }), "6800010000"},
		{"push 0x80", emitted(func(b *x86CodeBuilder) { b.pushImm(0x80) }), "6880000000"},
		{"push rcx", emitted(func(b *x86CodeBuilder) { b.pushReg(1) }), "51"},
		{"push r11", emitted(func(b *x86CodeBuilder) { b.pushReg(11) }), "4153"},
	}
	for _, tc := range cases {
		if want := mustHex(t, tc.want); !bytes.Equal(tc.got, want) {
			t.Errorf("%s = %x, want %x", tc.name, tc.got, want)
		}
	}
}

func TestX86SyscallEntryBytes(t *testing.T) {
	img := buildX86Kernel(0xffffff8000002000)
	want := mustHex(t, "0f01f8"+ // swapgs
		"654889242580000000"+ // mov %rsp, %gs:0x80
		"65488b242588000000"+ // mov %gs:0x88, %rsp
		"6a2b"+ // push $0x2b
		"65ff342580000000"+ // push %gs:0x80
		"4153"+ // push %r11
		"6a33"+ // push $0x33
		"51"+ // push %rcx
		"6a00"+ // push $0
		"6800010000") // push $0x100
	if got := img.Code[x86CodeSyscall : x86CodeSyscall+len(want)]; !bytes.Equal(got, want) {
		t.Errorf("SYSCALL entry = %x, want %x", got, want)
	}
	// The SYSCALL entry has already executed SWAPGS, so it joins after it.
	jmp := img.Code[x86CodeSyscall+len(want):]
	if jmp[0] != 0xe9 {
		t.Fatalf("no JMP after the frame setup: %x", jmp[:5])
	}
	rel := int32(binary.LittleEndian.Uint32(jmp[1:5]))
	if target := x86CodeSyscall + len(want) + 5 + int(rel); target != x86CodeSpill {
		t.Errorf("SYSCALL joins the common code at %#x, want %#x (after SWAPGS)", target, x86CodeSpill)
	}
}

func TestX86ExceptionStubs(t *testing.T) {
	img := buildX86Kernel(0xffffff8000002000)
	stubAt := func(vec int) int {
		if vec == x86VecInt80 {
			return x86CodeInt80
		}
		return x86CodeStubs + vec*x86CodeStubSize
	}
	vectors := make([]int, 0, 33)
	for v := range x86ExceptionVectors {
		vectors = append(vectors, v)
	}
	vectors = append(vectors, x86VecInt80)
	for _, vec := range vectors {
		off := stubAt(vec)
		code := img.Code[off:]
		pos := 0
		if !x86VectorHasErrorCode(vec) {
			if code[0] != 0x6a || code[1] != 0 {
				t.Errorf("vector %d: no dummy error code push, bytes %x", vec, code[:4])
				continue
			}
			pos = 2
		}
		var pushedVec int
		switch code[pos] {
		case 0x6a:
			pushedVec = int(code[pos+1])
			pos += 2
		case 0x68:
			pushedVec = int(binary.LittleEndian.Uint32(code[pos+1:]))
			pos += 5
		default:
			t.Errorf("vector %d: stub does not push the vector, bytes %x", vec, code[:6])
			continue
		}
		if pushedVec != vec {
			t.Errorf("vector %d: stub pushes %d", vec, pushedVec)
		}
		if code[pos] != 0xe9 {
			t.Errorf("vector %d: stub does not end in JMP", vec)
			continue
		}
		rel := int32(binary.LittleEndian.Uint32(code[pos+1:]))
		if target := off + pos + 5 + int(rel); target != x86CodeCommon {
			t.Errorf("vector %d: JMP target %#x, want %#x", vec, target, x86CodeCommon)
		}
		if vec < x86ExceptionVectors && pos+5 > x86CodeStubSize {
			t.Errorf("vector %d: stub is %d bytes, slot is %d", vec, pos+5, x86CodeStubSize)
		}
	}
}

func TestX86SpillAndReloadAreSymmetric(t *testing.T) {
	img := buildX86Kernel(0xffffff8000002000)
	// Spill: SWAPGS then one store per register except RSP, in hardware order.
	spill := img.Code[x86CodeCommon:]
	if !bytes.Equal(spill[:3], []byte{0x0f, 0x01, 0xf8}) {
		t.Fatalf("common routine does not start with SWAPGS: %x", spill[:3])
	}
	disp := func(code []byte) uint32 { return binary.LittleEndian.Uint32(code[5:9]) }
	pos := 3
	var stores, loads []uint32
	for reg := range 16 {
		if reg == x86RSP {
			continue
		}
		insn := spill[pos : pos+9]
		if insn[2] != 0x89 || insn[3]>>3&7 != byte(reg&7) {
			t.Fatalf("spill of register %d: bytes %x", reg, insn)
		}
		stores = append(stores, disp(insn))
		pos += 9
	}
	reload := img.Code[x86CodeReload:]
	pos = 0
	for reg := range 16 {
		if reg == x86RSP {
			continue
		}
		insn := reload[pos : pos+9]
		if insn[2] != 0x8b || insn[3]>>3&7 != byte(reg&7) {
			t.Fatalf("reload of register %d: bytes %x", reg, insn)
		}
		loads = append(loads, disp(insn))
		pos += 9
	}
	for i := range stores {
		if stores[i] != loads[i] {
			t.Errorf("register slot %d: spilled to %#x but reloaded from %#x", i, stores[i], loads[i])
		}
	}
	// After the loads: ADD $16,%RSP; SWAPGS; IRETQ.
	if tail := reload[pos : pos+9]; !bytes.Equal(tail, mustHex(t, "4883c4100f01f848cf")) {
		t.Errorf("reload tail = %x, want ADD rsp,16; SWAPGS; IRETQ", tail)
	}
	if img.Code[img.HLTOffset] != 0xf4 {
		t.Errorf("byte at HLTOffset %#x is %#x, want HLT", img.HLTOffset, img.Code[img.HLTOffset])
	}
	// The CR2 store follows the register stores.
	cr2 := spill[3+15*9:]
	if !bytes.Equal(cr2[:3], []byte{0x0f, 0x20, 0xd0}) {
		t.Errorf("CR2 read = %x, want MOV rax,cr2", cr2[:3])
	}
	if got, want := disp(cr2[3:12]), uint32(x86OffCR2); got != want {
		t.Errorf("CR2 stored at gs:%#x, want gs:%#x", got, want)
	}
}

func TestX86CommPageLayout(t *testing.T) {
	var c x86CommPage
	if got := unsafe.Sizeof(c); got != 4096 {
		t.Fatalf("x86CommPage size = %d, want 4096", got)
	}
	checks := map[string]struct{ got, want uintptr }{
		"Regs":    {unsafe.Offsetof(c.Regs), 0},
		"Scratch": {unsafe.Offsetof(c.Scratch), 128},
		"Stack":   {unsafe.Offsetof(c.Stack), 136},
		"CR2":     {unsafe.Offsetof(c.CR2), 144},
		"TSS":     {unsafe.Offsetof(c.TSS), 256},
	}
	for name, ck := range checks {
		if ck.got != ck.want {
			t.Errorf("offset of %s = %d, want %d", name, ck.got, ck.want)
		}
	}
	if got := unsafe.Sizeof(c.TSS); got != 104 {
		t.Errorf("TSS size = %d, want 104", got)
	}
	// The frame fields sit directly below the top of the stack page, seven words.
	if x86FrameVector != x86StackPageSize-7*8 || x86FrameSS != x86StackPageSize-8 {
		t.Errorf("frame offsets %d..%d do not describe seven words", x86FrameVector, x86FrameSS)
	}
}

func TestX86GDT(t *testing.T) {
	img := buildX86Kernel(0xffffff8000002000)
	desc := func(sel uint64) uint64 { return binary.LittleEndian.Uint64(img.GDT[sel&^7:]) }
	type fields struct {
		accessType, dpl           uint64
		present, long, db, system bool
	}
	decode := func(d uint64) fields {
		access := d >> 40 & 0xff
		flags := d >> 52 & 0xf
		return fields{
			accessType: access & 0xf, dpl: access >> 5 & 3,
			present: access&0x80 != 0, system: access&0x10 != 0,
			long: flags&2 != 0, db: flags&4 != 0,
		}
	}
	cases := []struct {
		name string
		sel  uint64
		want fields
	}{
		{"kernel code", x86KernelCS, fields{0xb, 0, true, true, false, true}},
		{"kernel data", x86KernelSS, fields{0x3, 0, true, false, true, true}},
		{"user code 32", x86UserCS32, fields{0xb, 3, true, false, true, true}},
		{"user data", x86UserSS, fields{0x3, 3, true, false, true, true}},
		{"user code 64", x86UserCS64, fields{0xb, 3, true, true, false, true}},
	}
	for _, tc := range cases {
		if got := decode(desc(tc.sel)); got != tc.want {
			t.Errorf("%s (selector %#x) = %+v, want %+v", tc.name, tc.sel, got, tc.want)
		}
	}
	if x86GDTLimit != 7*8-1 {
		t.Errorf("GDT limit = %d, want %d", x86GDTLimit, 7*8-1)
	}
	// STAR uses selector+16 for SYSRET: the layout satisfies it even though the
	// stub returns with IRETQ.
	if x86UserCS32+16 != x86UserCS64 || x86UserCS32+8 != x86UserSS {
		t.Error("user selectors are not laid out for SYSRET")
	}
}

func TestX86IDTGates(t *testing.T) {
	const codeVA uint64 = 0xffffff8000002000
	img := buildX86Kernel(codeVA)
	gate := func(vec int) (handler uint64, sel uint16, attr byte) {
		g := img.IDT[vec*16 : vec*16+16]
		handler = uint64(binary.LittleEndian.Uint16(g[0:])) |
			uint64(binary.LittleEndian.Uint16(g[6:]))<<16 |
			uint64(binary.LittleEndian.Uint32(g[8:]))<<32
		return handler, binary.LittleEndian.Uint16(g[2:]), g[5]
	}
	for vec := range x86ExceptionVectors {
		handler, sel, attr := gate(vec)
		if want := codeVA + uint64(x86CodeStubs+vec*x86CodeStubSize); handler != want {
			t.Errorf("vector %d handler = %#x, want %#x", vec, handler, want)
		}
		wantAttr := byte(0x8e)
		if vec == x86VecBreakpoint {
			wantAttr = 0xee
		}
		if sel != uint16(x86KernelCS) || attr != wantAttr {
			t.Errorf("vector %d selector %#x attr %#x, want %#x %#x", vec, sel, attr, x86KernelCS, wantAttr)
		}
	}
	handler, _, attr := gate(x86VecInt80)
	if handler != codeVA+uint64(x86CodeInt80) || attr != 0xee {
		t.Errorf("INT 0x80 gate = %#x attr %#x, want the DPL 3 stub", handler, attr)
	}
	for _, vec := range []int{32, 0x21, 0x7f, 0x81, 255} {
		if _, _, attr := gate(vec); attr&0x80 != 0 {
			t.Errorf("vector %d is present: a stray INT n would reach the stub", vec)
		}
	}
	// Interrupt gates only: trap gates keep IF set inside the stub.
	if _, _, attr := gate(x86VecPageFault); attr&0xf != 0xe {
		t.Errorf("page fault gate type = %#x, want an interrupt gate (0xe)", attr&0xf)
	}
}

func TestX86TSS(t *testing.T) {
	var tss [104]byte
	tss[50] = 0xff
	x86FillTSS(tss[:], 0xffffff8000012000)
	if got := binary.LittleEndian.Uint64(tss[x86TSSRSP0Offset:]); got != 0xffffff8000012000 {
		t.Errorf("RSP0 = %#x", got)
	}
	if tss[50] != 0 {
		t.Error("the template keeps stale bytes")
	}
	if got := binary.LittleEndian.Uint16(tss[x86TSSIOMapOffset:]); got != 104 {
		t.Errorf("I/O map base = %d, want 104 (past the limit)", got)
	}
}

func TestX86PageTableDescriptors(t *testing.T) {
	cases := []struct {
		name string
		at   hostarch.AccessType
		w    bool
		nx   bool
	}{
		{"read", hostarch.Read, false, true},
		{"read write", hostarch.ReadWrite, true, true},
		{"read execute", hostarch.AccessType{Read: true, Execute: true}, false, false},
		{"execute only", hostarch.Execute, false, false},
	}
	for _, tc := range cases {
		d := x86UserLeafDescriptor(0x2_0000_5000, tc.at)
		if d&x86PTEAddrMask != 0x2_0000_5000 {
			t.Errorf("%s: address %#x", tc.name, d&x86PTEAddrMask)
		}
		if d&x86PTEPresent == 0 || d&x86PTEUser == 0 || d&x86PTEAccessed == 0 || d&x86PTEDirty == 0 {
			t.Errorf("%s: descriptor %#x lacks P, U, A or D", tc.name, d)
		}
		if (d&x86PTEWritable != 0) != tc.w || (d&x86PTENX != 0) != tc.nx {
			t.Errorf("%s: descriptor %#x has W=%v NX=%v, want W=%v NX=%v", tc.name, d, d&x86PTEWritable != 0, d&x86PTENX != 0, tc.w, tc.nx)
		}
	}
	if d := x86UserLeafDescriptor(0x1000, hostarch.NoAccess); d != 0 {
		t.Errorf("a page without access has descriptor %#x", d)
	}
	k := x86KernelLeafDescriptor(0x3000, false, true)
	if k&x86PTEUser != 0 || k&x86PTEWritable != 0 || k&x86PTENX != 0 {
		t.Errorf("kernel code descriptor %#x must be supervisor, read-only, executable", k)
	}
	k = x86KernelLeafDescriptor(0x3000, true, false)
	if k&x86PTEUser != 0 || k&x86PTEWritable == 0 || k&x86PTENX == 0 {
		t.Errorf("kernel data descriptor %#x must be supervisor, writable, no-execute", k)
	}
	if td := x86MakeKernelTableDescriptor(0x5000); td&x86PTEUser != 0 {
		t.Errorf("kernel table descriptor %#x is user-accessible", td)
	}
	if gpa, ok := x86TableDescriptorGPA(x86MakeTableDescriptor(0x7000)); !ok || gpa != 0x7000 {
		t.Errorf("table descriptor round trip = (%#x, %v)", gpa, ok)
	}
	if _, ok := x86TableDescriptorGPA(0); ok {
		t.Error("an empty descriptor decodes as a table")
	}
}

func TestDecodeX86StubExit(t *testing.T) {
	const rip, cr2, userCS = 0x400100, 0x7000dead, 0x33
	cases := []struct {
		name  string
		vec   uint64
		err   uint64
		dr6   uint64
		cs    uint64
		kind  exitKind
		signo linux.Signal
		code  int32
		addr  uint64
		at    hostarch.AccessType
	}{
		{name: "syscall", vec: x86VecSyscall, kind: exitSyscall},
		{name: "int 0x80", vec: x86VecInt80, kind: exitSyscall},
		{name: "bounce", vec: x86VecBounce, kind: exitBounce},
		{name: "page fault not present read", vec: x86VecPageFault, err: x86PFUser, kind: exitSignal,
			signo: linux.SIGSEGV, code: sigSegvMap, addr: cr2, at: hostarch.Read},
		{name: "page fault not present write", vec: x86VecPageFault, err: x86PFUser | x86PFWrite, kind: exitSignal,
			signo: linux.SIGSEGV, code: sigSegvMap, addr: cr2, at: hostarch.Write},
		{name: "page fault protection write", vec: x86VecPageFault, err: x86PFUser | x86PFWrite | x86PFPresent, kind: exitSignal,
			signo: linux.SIGSEGV, code: sigSegvAcc, addr: cr2, at: hostarch.Write},
		{name: "page fault instruction fetch", vec: x86VecPageFault, err: x86PFUser | x86PFInstrFetch | x86PFPresent, kind: exitSignal,
			signo: linux.SIGSEGV, code: sigSegvAcc, addr: cr2, at: hostarch.Execute},
		{name: "divide", vec: x86VecDivide, kind: exitSignal, signo: linux.SIGFPE, code: sigFPEIntDiv, addr: rip},
		{name: "overflow", vec: x86VecOverflow, kind: exitSignal, signo: linux.SIGFPE, code: sigFPEIntOvf, addr: rip},
		{name: "x87", vec: x86VecX87, kind: exitSignal, signo: linux.SIGFPE, code: sigFPEFltInv, addr: rip},
		{name: "simd", vec: x86VecSIMD, kind: exitSignal, signo: linux.SIGFPE, code: sigFPEFltInv, addr: rip},
		{name: "debug single step", vec: x86VecDebug, dr6: x86DR6BS, kind: exitSignal, signo: linux.SIGTRAP, code: sigTrapTrace, addr: rip},
		{name: "debug hardware breakpoint", vec: x86VecDebug, dr6: 1, kind: exitSignal, signo: linux.SIGTRAP, code: sigTrapHWBkp, addr: rip},
		{name: "debug other", vec: x86VecDebug, kind: exitSignal, signo: linux.SIGTRAP, code: sigTrapBrkpt, addr: rip},
		{name: "breakpoint", vec: x86VecBreakpoint, kind: exitSignal, signo: linux.SIGTRAP, code: siKernel},
		{name: "invalid opcode", vec: x86VecInvalidOp, kind: exitSignal, signo: linux.SIGILL, code: sigIllOpn, addr: rip},
		{name: "alignment check", vec: x86VecAlignment, kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrAln},
		{name: "general protection", vec: x86VecGeneralProt, kind: exitSignal, signo: linux.SIGSEGV, code: siKernel, addr: rip},
		{name: "stack fault", vec: x86VecStackFault, kind: exitSignal, signo: linux.SIGSEGV, code: siKernel, addr: rip},
		{name: "double fault", vec: x86VecDoubleFault, kind: exitInternal},
		{name: "machine check", vec: x86VecMachineChk, kind: exitInternal},
		{name: "device not available", vec: x86VecDeviceNA, kind: exitInternal},
		{name: "unknown vector", vec: 200, kind: exitInternal},
		{name: "fault in the stub", vec: x86VecPageFault, cs: x86KernelCS, kind: exitInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := tc.cs
			if cs == 0 {
				cs = userCS
			}
			act := decodeX86StubExit(tc.vec, tc.err, cr2, rip, cs, tc.dr6)
			if act.kind != tc.kind {
				t.Fatalf("kind = %d, want %d (err=%v)", act.kind, tc.kind, act.err)
			}
			if tc.kind == exitInternal && act.err == nil {
				t.Error("an internal exit carries no error")
			}
			if tc.kind == exitSignal {
				if act.info.Signo != int32(tc.signo) || act.info.Code != tc.code || act.info.Addr() != tc.addr || act.at != tc.at {
					t.Errorf("got signal %d code %d addr %#x access %v, want %d code %d addr %#x access %v",
						act.info.Signo, act.info.Code, act.info.Addr(), act.at, tc.signo, tc.code, tc.addr, tc.at)
				}
			}
		})
	}
}

func TestDecodeEPTViolation(t *testing.T) {
	act := decodeEPTViolation(eptQualWrite, 0x7fff0000)
	if act.kind != exitSignal || act.info.Signo != int32(linux.SIGBUS) || act.info.Code != sigBusAdrErr ||
		act.info.Addr() != 0x7fff0000 || act.at != hostarch.Write {
		t.Errorf("EPT write violation = %+v (info %+v)", act, act.info)
	}
	if act := decodeEPTViolation(eptQualFetch, 0x1000); act.at != hostarch.Execute {
		t.Errorf("EPT fetch violation access = %v, want Execute", act.at)
	}
}
