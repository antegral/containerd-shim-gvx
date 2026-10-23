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
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// This file decodes ARM64 exception syndromes into Linux behavior. It has no
// host dependency, so unit tests exercise it on every OS.

// ESR_ELx exception classes (ARM DDI 0487, D17.2.37).
const (
	ecUnknown      = 0x00
	ecWFx          = 0x01
	ecIllegalState = 0x0e
	ecSVC64        = hvcommon.ECSVC64
	ecHVC64        = 0x16
	ecSysReg       = 0x18
	ecInstrAbort   = hvcommon.ECInstrAbortLower
	ecPCAlignment  = 0x22
	ecDataAbort    = hvcommon.ECDataAbortLower
	ecSPAlignment  = 0x26
	ecBreakpoint   = 0x30
	ecBreakpointEL = 0x31
	ecSoftStep     = 0x32
	ecSoftStepEL   = 0x33
	ecWatchpoint   = 0x34
	ecWatchpointEL = 0x35
	ecBRK64        = 0x3c
)

// Fault status codes in ESR_ELx.ISS for aborts.
const (
	fscTranslationL0 = 0x04
	fscTranslationL3 = 0x07
	fscPermissionL1  = 0x0d
	fscPermissionL3  = 0x0f
	fscSyncExternal  = 0x10
	fscAlignment     = 0x21

	issS1PTW = 1 << 7 // The abort happened during a stage-1 table walk.
)

func esrEC(esr uint64) uint64  { return esr >> 26 & 0x3f }
func esrFSC(esr uint64) uint64 { return esr & 0x3f }

// decodeStubExit decodes the state that the EL1 stub spilled: the vector slot,
// ESR_EL1, FAR_EL1, ELR_EL1 and SP_EL0 of the guest exception.
func decodeStubExit(vec, esr, far, pc, sp uint64) exitAction {
	if vec != vecLowerELSync {
		return exitAction{kind: exitInternal, err: fmt.Errorf(
			"hvf: unexpected guest exception vector %d (esr=%#x far=%#x elr=%#x)", vec, esr, far, pc)}
	}
	switch ec := esrEC(esr); ec {
	case ecSVC64:
		return exitAction{kind: exitSyscall}
	case ecInstrAbort, ecDataAbort:
		return decodeUserAbort(esr, far)
	case ecPCAlignment:
		return signalAction(linux.SIGBUS, sigBusAdrAln, far, hostarch.NoAccess)
	case ecSPAlignment:
		// FAR_EL1 is architecturally unknown for an SP alignment fault.
		return signalAction(linux.SIGBUS, sigBusAdrAln, sp, hostarch.NoAccess)
	case ecBRK64:
		return signalAction(linux.SIGTRAP, sigTrapBrkpt, pc, hostarch.NoAccess)
	case ecSoftStep, ecSoftStepEL:
		return signalAction(linux.SIGTRAP, sigTrapTrace, pc, hostarch.NoAccess)
	case ecBreakpoint, ecBreakpointEL:
		return signalAction(linux.SIGTRAP, sigTrapHWBkp, pc, hostarch.NoAccess)
	case ecWatchpoint, ecWatchpointEL:
		return signalAction(linux.SIGTRAP, sigTrapHWBkp, far, hostarch.NoAccess)
	case ecSysReg:
		return exitAction{kind: exitSysReg}
	default:
		// Undefined instructions (EC 0), illegal execution state, an HVC or
		// SMC from EL0, and every unlisted class behave as SIGILL, as Linux does.
		return signalAction(linux.SIGILL, sigIllIllOpc, pc, hostarch.NoAccess)
	}
}

// decodeUserAbort maps a stage-1 instruction or data abort from EL0 to SIGSEGV
// or SIGBUS, with the access type taken from the syndrome.
func decodeUserAbort(esr, far uint64) exitAction {
	addr := uint64(hostarch.UntaggedUserAddr(hostarch.Addr(far)))
	at := hostarch.ESRAccessType(esr)
	switch fsc := esrFSC(esr); {
	case fsc == fscAlignment:
		return signalAction(linux.SIGBUS, sigBusAdrAln, addr, at)
	case fsc >= fscSyncExternal && fsc < fscAlignment:
		return signalAction(linux.SIGBUS, sigBusAdrErr, addr, at)
	case fsc >= fscTranslationL0 && fsc <= fscTranslationL3:
		return signalAction(linux.SIGSEGV, sigSegvMap, addr, at)
	default:
		return signalAction(linux.SIGSEGV, sigSegvAcc, addr, at)
	}
}

// decodeHypervisorExit decodes an exception that Hypervisor.framework reports
// directly, without the EL1 stub. The syndrome is ESR_EL2 and virtualAddress
// is the guest virtual address of an abort.
func decodeHypervisorExit(syndrome, virtualAddress, physicalAddress uint64) exitAction {
	switch ec := esrEC(syndrome); ec {
	case ecInstrAbort, ecDataAbort:
		return decodeStage2Abort(syndrome, virtualAddress, physicalAddress)
	case ecSysReg:
		return exitAction{kind: exitSysReg}
	case ecWFx:
		return exitAction{kind: exitWFx}
	default:
		return exitAction{kind: exitInternal, err: fmt.Errorf(
			"hvf: unexpected hypervisor exception class %#x (syndrome=%#x va=%#x ipa=%#x)",
			ec, syndrome, virtualAddress, physicalAddress)}
	}
}

// decodeStage2Abort classifies an abort the stage-2 tables raise. Stage-1
// tables only name guest physical pages that Stage-2 maps, so an abort here
// means the guest touched memory with no backing page.
func decodeStage2Abort(syndrome, va, ipa uint64) exitAction {
	if syndrome&issS1PTW != 0 {
		return exitAction{kind: exitInternal, err: fmt.Errorf(
			"hvf: stage-2 abort during a stage-1 table walk (syndrome=%#x va=%#x ipa=%#x)", syndrome, va, ipa)}
	}
	addr := uint64(hostarch.UntaggedUserAddr(hostarch.Addr(va)))
	at := hostarch.ESRAccessType(syndrome)
	switch fsc := esrFSC(syndrome); {
	case fsc >= fscPermissionL1 && fsc <= fscPermissionL3:
		return signalAction(linux.SIGSEGV, sigSegvAcc, addr, at)
	case fsc >= fscTranslationL0 && fsc <= fscTranslationL3:
		// Nonexistent physical page: Linux reports this as BUS_ADRERR.
		return signalAction(linux.SIGBUS, sigBusAdrErr, addr, at)
	default:
		return signalAction(linux.SIGBUS, sigBusObjErr, addr, at)
	}
}

// sysRegISS holds the fields of the ISS of an EC 0x18 exception.
type sysRegISS struct {
	read                    bool
	rt                      uint32
	op0, op1, crn, crm, op2 uint32
}

func decodeSysRegISS(esr uint64) sysRegISS {
	return sysRegISS{
		read: esr&1 != 0,
		rt:   uint32(esr >> 5 & 0x1f),
		crm:  uint32(esr >> 1 & 0xf),
		crn:  uint32(esr >> 10 & 0xf),
		op1:  uint32(esr >> 14 & 0x7),
		op2:  uint32(esr >> 17 & 0x7),
		op0:  uint32(esr >> 20 & 0x3),
	}
}

func (s sysRegISS) key() uint32 {
	return s.op0<<14 | s.op1<<11 | s.crn<<7 | s.crm<<3 | s.op2
}

// Encodings of the registers that userspace may read, as the key of sysRegISS.
var (
	keyMIDR        = sysRegISS{op0: 3, op1: 0, crn: 0, crm: 0, op2: 0}.key()
	keyREVIDR      = sysRegISS{op0: 3, op1: 0, crn: 0, crm: 0, op2: 6}.key()
	keyIDAA64PFR0  = sysRegISS{op0: 3, op1: 0, crn: 0, crm: 4, op2: 0}.key()
	keyIDAA64PFR1  = sysRegISS{op0: 3, op1: 0, crn: 0, crm: 4, op2: 1}.key()
	keyIDAA64ISAR0 = sysRegISS{op0: 3, op1: 0, crn: 0, crm: 6, op2: 0}.key()
	keyIDAA64ISAR1 = sysRegISS{op0: 3, op1: 0, crn: 0, crm: 6, op2: 1}.key()
	keyIDAA64MMFR0 = sysRegISS{op0: 3, op1: 0, crn: 0, crm: 7, op2: 0}.key()
	keyIDAA64MMFR1 = sysRegISS{op0: 3, op1: 0, crn: 0, crm: 7, op2: 1}.key()
	keyIDAA64MMFR2 = sysRegISS{op0: 3, op1: 0, crn: 0, crm: 7, op2: 2}.key()
	keyCNTPCT      = sysRegISS{op0: 3, op1: 3, crn: 14, crm: 0, op2: 1}.key()
	keyCNTVCT      = sysRegISS{op0: 3, op1: 3, crn: 14, crm: 0, op2: 2}.key()
)

// ID register fields that this backend hides from the guest.
const (
	// ID_AA64PFR0_EL1: SVE, MPAM, AMU.
	idAA64PFR0Hide uint64 = 0xf<<32 | 0xff<<40
	// ID_AA64PFR1_EL1: MTE, MPAM_frac, SME, MTE_frac.
	idAA64PFR1Hide uint64 = 0xf<<8 | 0xf<<16 | 0xf<<24 | 0xf<<40
	// ID_AA64ISAR1_EL1: APA, API, GPA, GPI (pointer authentication).
	idAA64ISAR1Hide uint64 = 0xf<<4 | 0xf<<8 | 0xf<<24 | 0xf<<28
)

// idRegisters holds the values that EL0 reads of the ID registers and the
// system counter. They come
// from the vCPU, with the features that this backend does not virtualize
// hidden: scalable vectors, memory tagging, and pointer authentication.
type idRegisters struct {
	midr, pfr0, pfr1, isar0, isar1, mmfr0, mmfr1, mmfr2 uint64
	// counter reads the hardware system counter. Hypervisor.framework traps
	// EL0 reads of CNTPCT_EL0, so the host answers them.
	counter func() uint64
}

// emulateSysRegRead returns the value a trapped MRS must produce. It reports
// false for writes and for registers that Linux does not expose, so the guest
// receives SIGILL for them.
func (ids *idRegisters) emulateSysRegRead(iss sysRegISS) (uint64, bool) {
	if !iss.read {
		return 0, false
	}
	switch iss.key() {
	case keyMIDR:
		return ids.midr, true
	case keyREVIDR:
		return 0, true
	case keyIDAA64PFR0:
		return ids.pfr0 &^ idAA64PFR0Hide, true
	case keyIDAA64PFR1:
		return ids.pfr1 &^ idAA64PFR1Hide, true
	case keyIDAA64ISAR0:
		return ids.isar0, true
	case keyIDAA64ISAR1:
		return ids.isar1 &^ idAA64ISAR1Hide, true
	case keyIDAA64MMFR0:
		return ids.mmfr0, true
	case keyIDAA64MMFR1:
		return ids.mmfr1, true
	case keyIDAA64MMFR2:
		return ids.mmfr2, true
	case keyCNTPCT, keyCNTVCT:
		if ids.counter != nil {
			return ids.counter(), true
		}
	}
	return 0, false
}
