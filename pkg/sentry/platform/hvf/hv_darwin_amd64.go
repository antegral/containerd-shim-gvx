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
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

var errMachAbsTimeMissing = errors.New("hvf: libSystem does not export mach_absolute_time")

// x86 Hypervisor.framework register identifiers (hv_arch_x86.h).
const (
	hvX86RIP    uint32 = 0
	hvX86RFLAGS uint32 = 1
	hvX86RAX    uint32 = 2
	hvX86RCX    uint32 = 3
	hvX86RDX    uint32 = 4
	hvX86RBX    uint32 = 5
	hvX86RSI    uint32 = 6
	hvX86RDI    uint32 = 7
	hvX86RSP    uint32 = 8
	hvX86RBP    uint32 = 9
	hvX86R8     uint32 = 10
	hvX86CS     uint32 = 18
	hvX86SS     uint32 = 19
	hvX86CR3    uint32 = 39
	hvX86DR6    uint32 = 47
	hvX86XCR0   uint32 = 50
)

// hvX86GPR maps a hardware register number (RAX=0, RCX=1, RDX=2, RBX=3, RSP=4,
// RBP=5, RSI=6, RDI=7, R8 to R15=8 to 15) to the framework register identifier.
// The framework numbers its registers differently.
var hvX86GPR = [16]uint32{
	hvX86RAX, hvX86RCX, hvX86RDX, hvX86RBX,
	hvX86RSP, hvX86RBP, hvX86RSI, hvX86RDI,
	hvX86R8, hvX86R8 + 1, hvX86R8 + 2, hvX86R8 + 3,
	hvX86R8 + 4, hvX86R8 + 5, hvX86R8 + 6, hvX86R8 + 7,
}

// x86 MSR numbers (hv_arch_vmx.h).
const (
	msrSysenterCS  uint32 = 0x174
	msrSysenterESP uint32 = 0x175
	msrSysenterEIP uint32 = 0x176
	msrTSC         uint32 = 0x10
	msrSTAR        uint32 = 0xc0000081
	msrLSTAR       uint32 = 0xc0000082
	msrCSTAR       uint32 = 0xc0000083
	msrFMASK       uint32 = 0xc0000084
	msrFSBase      uint32 = 0xc0000100
	msrGSBase      uint32 = 0xc0000101
	msrKernelGS    uint32 = 0xc0000102
	msrTSCAux      uint32 = 0xc0000103
)

// Capability identifiers for hv_vmx_read_capability (hv_vmx.h).
const (
	hvVMXCapPinBased   uint32 = 0
	hvVMXCapProcBased  uint32 = 1
	hvVMXCapProcBased2 uint32 = 2
	hvVMXCapEntry      uint32 = 3
)

// hvCapVCPUMax is HV_CAP_VCPUMAX for hv_capability.
const hvCapVCPUMax uint64 = 0

// hvDeadlineForever is HV_DEADLINE_FOREVER.
const hvDeadlineForever = ^uint64(0)

// hvVCPUExit is empty on x86: the VMCS carries the exit information, which the
// code reads with hv_vmx_vcpu_read_vmcs.
type hvVCPUExit struct{}

type hvArchSymbols struct {
	capability     uintptr
	vcpuCreate     uintptr
	vcpuDestroy    uintptr
	vcpuRun        uintptr
	vcpuRunUntil   uintptr
	vcpuInterrupt  uintptr
	readRegister   uintptr
	writeRegister  uintptr
	readMSR        uintptr
	writeMSR       uintptr
	enableNative   uintptr
	readVMCS       uintptr
	writeVMCS      uintptr
	readCapability uintptr
	readFPState    uintptr
	writeFPState   uintptr
	invalidateTLB  uintptr
	machAbsTime    uintptr
}

func (s *hvSymbols) resolveArch(resolve func(string) (uintptr, error)) error {
	for _, entry := range []struct {
		name string
		dst  *uintptr
	}{
		{"hv_capability", &s.capability},
		{"hv_vcpu_create", &s.vcpuCreate},
		{"hv_vcpu_destroy", &s.vcpuDestroy},
		{"hv_vcpu_run", &s.vcpuRun},
		{"hv_vcpu_run_until", &s.vcpuRunUntil},
		{"hv_vcpu_interrupt", &s.vcpuInterrupt},
		{"hv_vcpu_read_register", &s.readRegister},
		{"hv_vcpu_write_register", &s.writeRegister},
		{"hv_vcpu_read_msr", &s.readMSR},
		{"hv_vcpu_write_msr", &s.writeMSR},
		{"hv_vcpu_enable_native_msr", &s.enableNative},
		{"hv_vmx_vcpu_read_vmcs", &s.readVMCS},
		{"hv_vmx_vcpu_write_vmcs", &s.writeVMCS},
		{"hv_vmx_read_capability", &s.readCapability},
		{"hv_vcpu_read_fpstate", &s.readFPState},
		{"hv_vcpu_write_fpstate", &s.writeFPState},
		{"hv_vcpu_invalidate_tlb", &s.invalidateTLB},
	} {
		sym, err := resolve(entry.name)
		if err != nil {
			return err
		}
		*entry.dst = sym
	}
	return nil
}

// hvVMMaxVCPUs returns the vCPU limit of the VM.
func hvVMMaxVCPUs() (int, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, err
	}
	var n uint64
	r1, _, _ := darwinSyscall6(s.capability, uintptr(hvCapVCPUMax), uintptr(unsafe.Pointer(&n)), 0, 0, 0, 0)
	if err := hvResult("hv_capability", r1); err != nil {
		return 0, err
	}
	return int(n), nil
}

// defaultIPABits is the guest physical address width this backend assumes. Every
// VT-x processor that supports EPT reports at least 36 physical address bits.
const defaultIPABits = 36

func hvDefaultIPABits() (uint, error) {
	return defaultIPABits, nil
}

// hvVCPUCreate creates a vCPU owned by the calling OS thread. The caller must
// hold runtime.LockOSThread for the life of the vCPU.
func hvVCPUCreate() (uint64, *hvVCPUExit, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, nil, err
	}
	var id uint32
	r1, _, _ := darwinSyscall6(s.vcpuCreate, uintptr(unsafe.Pointer(&id)), 0, 0, 0, 0, 0)
	if err := hvResult("hv_vcpu_create", r1); err != nil {
		return 0, nil, err
	}
	return uint64(id), nil, nil
}

// hvVCPUDestroy destroys a vCPU. Only the creating thread may call it.
func hvVCPUDestroy(id uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vcpuDestroy, uintptr(id), 0, 0, 0, 0, 0)
	return hvResult("hv_vcpu_destroy", r1)
}

// hvVCPURun runs the vCPU until the next exit, including exits that the
// framework handles itself.
func hvVCPURun(id uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vcpuRun, uintptr(id), 0, 0, 0, 0, 0)
	return hvResult("hv_vcpu_run", r1)
}

// hvVCPURunUntil runs the vCPU until an exit that needs the host or until the
// deadline in mach absolute time units. It reports HV_UNSUPPORTED when the
// processor lacks the VMX preemption timer.
func hvVCPURunUntil(id uint64, deadline uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vcpuRunUntil, uintptr(id), uintptr(deadline), 0, 0, 0, 0)
	return hvResult("hv_vcpu_run_until", r1)
}

// hvVCPUsExit forces a running vCPU to exit. Any thread may call it.
func hvVCPUsExit(id uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	vcpu := uint32(id)
	r1, _, _ := darwinSyscall6(s.vcpuInterrupt, uintptr(unsafe.Pointer(&vcpu)), 1, 0, 0, 0, 0)
	return hvResult("hv_vcpu_interrupt", r1)
}

// machAbsoluteTime returns mach_absolute_time, the unit of the run deadline.
func machAbsoluteTime() (uint64, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, err
	}
	if s.machAbsTime == 0 {
		name, err := unix.BytePtrFromString("mach_absolute_time")
		if err != nil {
			return 0, fmt.Errorf("hvf: symbol name: %w", err)
		}
		// RTLD_DEFAULT is (void *)-2.
		sym, _, _ := darwinSyscall6(addrOfDlsym(), ^uintptr(1), uintptr(unsafe.Pointer(name)), 0, 0, 0, 0)
		if sym == 0 {
			return 0, errMachAbsTimeMissing
		}
		s.machAbsTime = sym
	}
	t, _, _ := darwinSyscall6(s.machAbsTime, 0, 0, 0, 0, 0, 0)
	return uint64(t), nil
}

// machTimebase is mach_timebase_info_data_t: absolute time units convert to
// nanoseconds as units * Numer / Denom.
type machTimebase struct {
	Numer, Denom uint32
}

var timebase struct {
	once sync.Once
	tb   machTimebase
	err  error
}

// machTicks converts a duration in nanoseconds to mach absolute time units.
func machTicks(ns uint64) (uint64, error) {
	timebase.once.Do(func() {
		name, err := unix.BytePtrFromString("mach_timebase_info")
		if err != nil {
			timebase.err = fmt.Errorf("hvf: symbol name: %w", err)
			return
		}
		sym, _, _ := darwinSyscall6(addrOfDlsym(), ^uintptr(1), uintptr(unsafe.Pointer(name)), 0, 0, 0, 0)
		if sym == 0 {
			timebase.err = errors.New("hvf: libSystem does not export mach_timebase_info")
			return
		}
		r1, _, _ := darwinSyscall6(sym, uintptr(unsafe.Pointer(&timebase.tb)), 0, 0, 0, 0, 0)
		if r1 != 0 || timebase.tb.Numer == 0 {
			timebase.err = fmt.Errorf("hvf: mach_timebase_info failed (%d)", r1)
		}
	})
	if timebase.err != nil {
		return 0, timebase.err
	}
	return ns * uint64(timebase.tb.Denom) / uint64(timebase.tb.Numer), nil
}

func hvReadRegister(id uint64, reg uint32) (uint64, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, err
	}
	var val uint64
	r1, _, _ := darwinSyscall6(s.readRegister, uintptr(id), uintptr(reg), uintptr(unsafe.Pointer(&val)), 0, 0, 0)
	if err := hvResult("hv_vcpu_read_register", r1); err != nil {
		return 0, err
	}
	return val, nil
}

func hvWriteRegister(id uint64, reg uint32, val uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.writeRegister, uintptr(id), uintptr(reg), uintptr(val), 0, 0, 0)
	return hvResult("hv_vcpu_write_register", r1)
}

func hvReadMSR(id uint64, msr uint32) (uint64, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, err
	}
	var val uint64
	r1, _, _ := darwinSyscall6(s.readMSR, uintptr(id), uintptr(msr), uintptr(unsafe.Pointer(&val)), 0, 0, 0)
	if err := hvResult("hv_vcpu_read_msr", r1); err != nil {
		return 0, err
	}
	return val, nil
}

func hvWriteMSR(id uint64, msr uint32, val uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.writeMSR, uintptr(id), uintptr(msr), uintptr(val), 0, 0, 0)
	return hvResult("hv_vcpu_write_msr", r1)
}

// hvEnableNativeMSR lets the guest access an MSR without an exit.
func hvEnableNativeMSR(id uint64, msr uint32) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.enableNative, uintptr(id), uintptr(msr), 1, 0, 0, 0)
	return hvResult("hv_vcpu_enable_native_msr", r1)
}

func hvReadVMCS(id uint64, field uint32) (uint64, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, err
	}
	var val uint64
	r1, _, _ := darwinSyscall6(s.readVMCS, uintptr(id), uintptr(field), uintptr(unsafe.Pointer(&val)), 0, 0, 0)
	if err := hvResult("hv_vmx_vcpu_read_vmcs", r1); err != nil {
		return 0, err
	}
	return val, nil
}

func hvWriteVMCS(id uint64, field uint32, val uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.writeVMCS, uintptr(id), uintptr(field), uintptr(val), 0, 0, 0)
	return hvResult("hv_vmx_vcpu_write_vmcs", r1)
}

// hvReadCapability reads one VMX capability MSR value.
func hvReadCapability(field uint32) (uint64, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, err
	}
	var val uint64
	r1, _, _ := darwinSyscall6(s.readCapability, uintptr(field), uintptr(unsafe.Pointer(&val)), 0, 0, 0, 0)
	if err := hvResult("hv_vmx_read_capability", r1); err != nil {
		return 0, err
	}
	return val, nil
}

// hvReadFPState stores the XSAVE image of the vCPU into buf.
func hvReadFPState(id uint64, buf []byte) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.readFPState, uintptr(id), uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(len(buf)), 0, 0, 0)
	return hvResult("hv_vcpu_read_fpstate", r1)
}

// hvWriteFPState loads the XSAVE image in buf into the vCPU.
func hvWriteFPState(id uint64, buf []byte) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.writeFPState, uintptr(id), uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(len(buf)), 0, 0, 0)
	return hvResult("hv_vcpu_write_fpstate", r1)
}

func hvInvalidateTLB(id uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.invalidateTLB, uintptr(id), 0, 0, 0, 0, 0)
	return hvResult("hv_vcpu_invalidate_tlb", r1)
}

// hostXCR0 returns XCR0 of the host.
func hostXCR0() uint64
