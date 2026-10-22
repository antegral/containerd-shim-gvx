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
	"unsafe"
)

// Hypervisor.framework register identifiers (hv_vcpu_types.h).
const (
	hvRegX0   uint32 = 0
	hvRegPC   uint32 = 31
	hvRegFPCR uint32 = 32
	hvRegFPSR uint32 = 33
	hvRegCPSR uint32 = 34

	hvSimdFPRegQ0 uint32 = 0
)

// Hypervisor.framework system register identifiers (hv_vcpu_types.h).
const (
	hvSysRegIDAA64PFR0  uint32 = 0xc020
	hvSysRegIDAA64PFR1  uint32 = 0xc021
	hvSysRegIDAA64ISAR0 uint32 = 0xc030
	hvSysRegIDAA64ISAR1 uint32 = 0xc031
	hvSysRegIDAA64MMFR0 uint32 = 0xc038
	hvSysRegIDAA64MMFR1 uint32 = 0xc039
	hvSysRegIDAA64MMFR2 uint32 = 0xc03a
	hvSysRegMIDR        uint32 = 0xc000
	hvSysRegSCTLR       uint32 = 0xc080
	hvSysRegCPACR       uint32 = 0xc082
	hvSysRegTTBR0       uint32 = 0xc100
	hvSysRegTTBR1       uint32 = 0xc101
	hvSysRegTCR         uint32 = 0xc102
	hvSysRegSPEL0       uint32 = 0xc208
	hvSysRegMAIR        uint32 = 0xc510
	hvSysRegVBAR        uint32 = 0xc600
	hvSysRegCNTKCTL     uint32 = 0xc708
	hvSysRegTPIDREL0    uint32 = 0xde82
	hvSysRegTPIDRRO     uint32 = 0xde83
	hvSysRegCNTVCTL     uint32 = 0xdf19
	hvSysRegSPEL1       uint32 = 0xe208
)

// Exit reasons of hv_vcpu_exit_t (hv_vcpu_types.h).
const (
	hvExitReasonCanceled  uint32 = 0
	hvExitReasonException uint32 = 1
	// hvExitReasonUnknown is HV_EXIT_REASON_UNKNOWN. The header says that it
	// should not happen in normal operation. See dispatchExit.
	hvExitReasonUnknown uint32 = 3
)

// hvVCPUExit mirrors hv_vcpu_exit_t. The framework owns the memory and keeps
// it valid until the vCPU is destroyed.
type hvVCPUExit struct {
	reason          uint32
	_               uint32
	syndrome        uint64
	virtualAddress  uint64
	physicalAddress uint64
}

type hvArchSymbols struct {
	vmGetMaxVCPUCount uintptr
	// vmConfigGetDefaultIPASize is optional: macOS 13 added it.
	vmConfigGetDefaultIPASize uintptr

	vcpuCreate       uintptr
	vcpuDestroy      uintptr
	vcpuRun          uintptr
	vcpusExit        uintptr
	vcpuGetReg       uintptr
	vcpuSetReg       uintptr
	vcpuGetSysReg    uintptr
	vcpuSetSysReg    uintptr
	vcpuGetSimdFPReg uintptr
}

func (s *hvSymbols) resolveArch(resolve func(string) (uintptr, error)) error {
	for _, entry := range []struct {
		name string
		dst  *uintptr
	}{
		{"hv_vm_get_max_vcpu_count", &s.vmGetMaxVCPUCount},
		{"hv_vcpu_create", &s.vcpuCreate},
		{"hv_vcpu_destroy", &s.vcpuDestroy},
		{"hv_vcpu_run", &s.vcpuRun},
		{"hv_vcpus_exit", &s.vcpusExit},
		{"hv_vcpu_get_reg", &s.vcpuGetReg},
		{"hv_vcpu_set_reg", &s.vcpuSetReg},
		{"hv_vcpu_get_sys_reg", &s.vcpuGetSysReg},
		{"hv_vcpu_set_sys_reg", &s.vcpuSetSysReg},
		{"hv_vcpu_get_simd_fp_reg", &s.vcpuGetSimdFPReg},
	} {
		sym, err := resolve(entry.name)
		if err != nil {
			return err
		}
		*entry.dst = sym
	}
	// The default IPA size query is optional.
	s.vmConfigGetDefaultIPASize, _ = resolve("hv_vm_config_get_default_ipa_size")
	return nil
}

// hvVCPUCreate creates a vCPU owned by the calling OS thread. The caller must
// hold runtime.LockOSThread for the life of the vCPU. The returned exit
// pointer stays valid until hvVCPUDestroy.
func hvVCPUCreate() (uint64, *hvVCPUExit, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, nil, err
	}
	var id uint64
	var exit *hvVCPUExit
	r1, _, _ := darwinSyscall6(s.vcpuCreate, uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&exit)), 0, 0, 0, 0)
	if err := hvResult("hv_vcpu_create", r1); err != nil {
		return 0, nil, err
	}
	return id, exit, nil
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

// hvVCPURun runs the vCPU until the next exit. Only the creating thread may
// call it.
func hvVCPURun(id uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vcpuRun, uintptr(id), 0, 0, 0, 0, 0)
	return hvResult("hv_vcpu_run", r1)
}

// hvVCPUsExit forces a running vCPU to exit. Any thread may call it. When the
// vCPU is not running, the next hv_vcpu_run returns immediately without
// entering the guest.
func hvVCPUsExit(id uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vcpusExit, uintptr(unsafe.Pointer(&id)), 1, 0, 0, 0, 0)
	return hvResult("hv_vcpus_exit", r1)
}

func hvGetReg(id uint64, reg uint32) (uint64, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, err
	}
	var val uint64
	r1, _, _ := darwinSyscall6(s.vcpuGetReg, uintptr(id), uintptr(reg), uintptr(unsafe.Pointer(&val)), 0, 0, 0)
	if err := hvResult("hv_vcpu_get_reg", r1); err != nil {
		return 0, err
	}
	return val, nil
}

func hvSetReg(id uint64, reg uint32, val uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vcpuSetReg, uintptr(id), uintptr(reg), uintptr(val), 0, 0, 0)
	return hvResult("hv_vcpu_set_reg", r1)
}

func hvGetSysReg(id uint64, reg uint32) (uint64, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, err
	}
	var val uint64
	r1, _, _ := darwinSyscall6(s.vcpuGetSysReg, uintptr(id), uintptr(reg), uintptr(unsafe.Pointer(&val)), 0, 0, 0)
	if err := hvResult("hv_vcpu_get_sys_reg", r1); err != nil {
		return 0, err
	}
	return val, nil
}

func hvSetSysReg(id uint64, reg uint32, val uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vcpuSetSysReg, uintptr(id), uintptr(reg), uintptr(val), 0, 0, 0)
	return hvResult("hv_vcpu_set_sys_reg", r1)
}

// hvGetSimdFPReg reads one 128-bit Q register. The framework passes the
// register through a pointer for the getter only. The setter takes a vector
// argument that integer-only calls cannot supply, so the stub restores the
// V registers from the CommPage instead.
func hvGetSimdFPReg(id uint64, q uint32) ([2]uint64, error) {
	s, err := loadSymbols()
	if err != nil {
		return [2]uint64{}, err
	}
	var val [2]uint64
	r1, _, _ := darwinSyscall6(s.vcpuGetSimdFPReg, uintptr(id), uintptr(hvSimdFPRegQ0+q), uintptr(unsafe.Pointer(&val)), 0, 0, 0)
	if err := hvResult("hv_vcpu_get_simd_fp_reg", r1); err != nil {
		return [2]uint64{}, err
	}
	return val, nil
}

// readSystemCounter returns CNTPCT_EL0, the hardware system counter. The host
// may read it at EL0 on macOS.
func readSystemCounter() uint64

// hvVMMaxVCPUs returns the vCPU limit of the VM.
func hvVMMaxVCPUs() (int, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, err
	}
	var n uint32
	r1, _, _ := darwinSyscall6(s.vmGetMaxVCPUCount, uintptr(unsafe.Pointer(&n)), 0, 0, 0, 0, 0)
	if err := hvResult("hv_vm_get_max_vcpu_count", r1); err != nil {
		return 0, err
	}
	return int(n), nil
}

// defaultIPABits is the IPA size of every Apple silicon VM that predates the
// hv_vm_config_get_default_ipa_size query.
const defaultIPABits = 36

// hvDefaultIPABits returns the guest physical address width of a VM that
// hv_vm_create creates with the default configuration.
func hvDefaultIPABits() (uint, error) {
	s, err := loadSymbols()
	if err != nil {
		return 0, err
	}
	if s.vmConfigGetDefaultIPASize == 0 {
		return defaultIPABits, nil
	}
	var bits uint32
	r1, _, _ := darwinSyscall6(s.vmConfigGetDefaultIPASize, uintptr(unsafe.Pointer(&bits)), 0, 0, 0, 0, 0)
	if err := hvResult("hv_vm_config_get_default_ipa_size", r1); err != nil {
		return 0, err
	}
	return uint(bits), nil
}
