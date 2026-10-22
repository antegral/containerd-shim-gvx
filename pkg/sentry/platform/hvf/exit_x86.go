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
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
)

// Page-fault error code bits (Intel SDM vol. 3, 4.7).
const (
	x86PFPresent    = 1 << 0
	x86PFWrite      = 1 << 1
	x86PFUser       = 1 << 2
	x86PFInstrFetch = 1 << 4
)

// DR6 bits that name the debug trap cause.
const (
	x86DR6B0toB3 = 0xf
	x86DR6BS     = 1 << 14
)

// Linux si_code values for x86 signals.
const (
	sigFPEIntDiv = 1
	sigFPEIntOvf = 2
	sigFPEFltInv = 7
	sigIllOpn    = 2
	siKernel     = 0x80
)

// decodeX86StubExit decodes the state that the Ring-0 stub spilled: the vector,
// the error code, CR2, and the RIP, CS and DR6 values. The mapping follows the
// KVM platform of gVisor, so a guest sees the same signals on every backend.
func decodeX86StubExit(vec, errCode, cr2, rip, cs, dr6 uint64) exitAction {
	if cs&3 != 3 {
		return exitAction{kind: exitInternal, err: fmt.Errorf(
			"hvf: exception %d in the Ring-0 stub (error code %#x, cr2 %#x, rip %#x, cs %#x)", vec, errCode, cr2, rip, cs)}
	}
	kernelSignal := func(signo linux.Signal) exitAction {
		return signalAction(signo, siKernel, rip, hostarch.NoAccess)
	}
	switch vec {
	case x86VecSyscall, x86VecInt80:
		return exitAction{kind: exitSyscall}
	case x86VecBounce:
		return exitAction{kind: exitBounce}
	case x86VecPageFault:
		return decodeX86PageFault(errCode, cr2)
	case x86VecDivide:
		return signalAction(linux.SIGFPE, sigFPEIntDiv, rip, hostarch.NoAccess)
	case x86VecOverflow:
		return signalAction(linux.SIGFPE, sigFPEIntOvf, rip, hostarch.NoAccess)
	case x86VecX87, x86VecSIMD:
		return signalAction(linux.SIGFPE, sigFPEFltInv, rip, hostarch.NoAccess)
	case x86VecDebug:
		code := int32(sigTrapBrkpt)
		switch {
		case dr6&x86DR6BS != 0:
			code = sigTrapTrace
		case dr6&x86DR6B0toB3 != 0:
			code = sigTrapHWBkp
		}
		return signalAction(linux.SIGTRAP, code, rip, hostarch.NoAccess)
	case x86VecBreakpoint:
		return signalAction(linux.SIGTRAP, siKernel, 0, hostarch.NoAccess)
	case x86VecInvalidOp:
		return signalAction(linux.SIGILL, sigIllOpn, rip, hostarch.NoAccess)
	case x86VecAlignment:
		return signalAction(linux.SIGBUS, sigBusAdrAln, 0, hostarch.NoAccess)
	case x86VecGeneralProt, x86VecSegNotPres, x86VecBound, x86VecInvalidTSS, x86VecStackFault:
		return kernelSignal(linux.SIGSEGV)
	default:
		return exitAction{kind: exitInternal, err: fmt.Errorf(
			"hvf: unexpected guest exception vector %d (error code %#x, rip %#x)", vec, errCode, rip)}
	}
}

// decodeX86PageFault maps a user page fault to SIGSEGV. A missing page is
// SEGV_MAPERR and a protection violation is SEGV_ACCERR, as on Linux.
func decodeX86PageFault(errCode, cr2 uint64) exitAction {
	at := hostarch.AccessType{
		Read:    errCode&(x86PFWrite|x86PFInstrFetch) == 0,
		Write:   errCode&x86PFWrite != 0,
		Execute: errCode&x86PFInstrFetch != 0,
	}
	code := int32(sigSegvMap)
	if errCode&x86PFPresent != 0 {
		code = sigSegvAcc
	}
	return signalAction(linux.SIGSEGV, code, cr2, at)
}

// VMX basic exit reasons that this backend reads (Intel SDM vol. 3, appendix C).
const (
	vmxExitExternalInterrupt = 1
	vmxExitCPUID             = 10
	vmxExitHLT               = 12
	vmxExitVMCALL            = 18
	vmxExitEPTViolation      = 48
	vmxExitPreemptionTimer   = 52

	vmxExitReasonMask      = 0xffff
	vmxExitEntryFailureBit = 1 << 31
)

// EPT violation exit qualification bits (Intel SDM vol. 3, table 27-7).
const (
	eptQualRead  = 1 << 0
	eptQualWrite = 1 << 1
	eptQualFetch = 1 << 2
)

// decodeEPTViolation maps an EPT violation, which means the guest touched a
// guest physical page without a host mapping, to SIGBUS with the faulting
// linear address. The guest physical address goes to the error text only.
func decodeEPTViolation(qualification, linearAddr uint64) exitAction {
	at := hostarch.AccessType{
		Read:    qualification&eptQualRead != 0,
		Write:   qualification&eptQualWrite != 0,
		Execute: qualification&eptQualFetch != 0,
	}
	return signalAction(linux.SIGBUS, sigBusAdrErr, linearAddr, at)
}
