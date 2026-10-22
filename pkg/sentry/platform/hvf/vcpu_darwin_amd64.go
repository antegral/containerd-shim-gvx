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
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// STATUS: this file has not run on hardware. The development host is an Apple
// silicon Mac, which cannot run the Intel Hypervisor.framework. The code builds
// and vets for darwin/amd64. The bluepill_x86.go generator and the exit
// decoder have unit tests on every host.
//
// Facts that the Hypervisor.framework headers and the Intel SDM document:
//   - VMCS field encodings, VMX exit reasons (CPUID 10, HLT 12, VMCALL 18, EPT
//     violation 48, preemption timer 52), the interruption-information bits
//     (hardware exception 3<<8, valid 1<<31), and the MSR numbers (hv_arch_vmx.h).
//   - hv_vcpu_run_until takes a deadline in mach absolute time units and returns
//     HV_UNSUPPORTED without the VMX preemption timer (hv.h). The code converts
//     nanoseconds with mach_timebase_info.
//   - hv_vcpu_read_fpstate and hv_vcpu_write_fpstate use the XSAVE layout and
//     size of the host processor (hv.h).
//   - VMCALL and CPUID always cause a VM exit in VMX non-root operation (SDM
//     vol. 3, 25.1.2), so the code treats a user-mode VMCALL as an illegal
//     instruction and emulates CPUID.
//   - A hardware exception injected with a valid vector enters the guest IDT
//     (SDM vol. 3, 26.5), and RIP stays at HLT after an HLT exit (SDM vol. 3,
//     27.1).
//
// Assumptions that no header or SDM text settles, and that need hardware:
//   - hv_vcpu_interrupt is not documented to persist for a vCPU that is not
//     running. The run slice (preemptSlice) bounds a lost kick.
//   - The framework adds the EPT, unrestricted-guest and VPID controls itself.
//     The header says only that the caller writes the controls. Public
//     examples (hvdos, QEMU) write cap2ctrl(cap, 0), as this code does.
//     hv_vmx_vcpu_get_cap_write_vmcs could confirm the allowed bits at run time.
//   - If the processor does not allow the load-EFER entry control, the guest
//     keeps the host LME, SCE and NXE bits. The field encodings and the control
//     bits (IA-32e guest 1<<9, load EFER 1<<15) are documented.
//   - hv_vcpu_enable_native_msr accepts every MSR that configure enables. The
//     header lists these MSR numbers and defers the supported set to the
//     documentation.
//
// VMCS field encodings (hv_arch_vmx.h).
const (
	vmcsGuestES         uint32 = 0x0800
	vmcsGuestCS         uint32 = 0x0802
	vmcsGuestSS         uint32 = 0x0804
	vmcsGuestDS         uint32 = 0x0806
	vmcsGuestFS         uint32 = 0x0808
	vmcsGuestGS         uint32 = 0x080a
	vmcsGuestLDTR       uint32 = 0x080c
	vmcsGuestTR         uint32 = 0x080e
	vmcsLinkPointer     uint32 = 0x2800
	vmcsGuestEFER       uint32 = 0x2806
	vmcsCtrlPin         uint32 = 0x4000
	vmcsCtrlCPU         uint32 = 0x4002
	vmcsCtrlExcBitmap   uint32 = 0x4004
	vmcsCtrlPFMask      uint32 = 0x4006
	vmcsCtrlPFMatch     uint32 = 0x4008
	vmcsCtrlEntry       uint32 = 0x4012
	vmcsCtrlEntryIRQ    uint32 = 0x4016
	vmcsCtrlCPU2        uint32 = 0x401e
	vmcsExitReason      uint32 = 0x4402
	vmcsGuestESLimit    uint32 = 0x4800
	vmcsGuestCSLimit    uint32 = 0x4802
	vmcsGuestSSLimit    uint32 = 0x4804
	vmcsGuestDSLimit    uint32 = 0x4806
	vmcsGuestFSLimit    uint32 = 0x4808
	vmcsGuestGSLimit    uint32 = 0x480a
	vmcsGuestLDTRLimit  uint32 = 0x480c
	vmcsGuestTRLimit    uint32 = 0x480e
	vmcsGuestGDTRLimit  uint32 = 0x4810
	vmcsGuestIDTRLimit  uint32 = 0x4812
	vmcsGuestESAR       uint32 = 0x4814
	vmcsGuestCSAR       uint32 = 0x4816
	vmcsGuestSSAR       uint32 = 0x4818
	vmcsGuestDSAR       uint32 = 0x481a
	vmcsGuestFSAR       uint32 = 0x481c
	vmcsGuestGSAR       uint32 = 0x481e
	vmcsGuestLDTRAR     uint32 = 0x4820
	vmcsGuestTRAR       uint32 = 0x4822
	vmcsGuestInterrupt  uint32 = 0x4824
	vmcsGuestActivity   uint32 = 0x4826
	vmcsGuestSysenterCS uint32 = 0x482a
	vmcsCtrlCR0Mask     uint32 = 0x6000
	vmcsCtrlCR4Mask     uint32 = 0x6002
	vmcsCtrlCR0Shadow   uint32 = 0x6004
	vmcsCtrlCR4Shadow   uint32 = 0x6006
	vmcsExitQual        uint32 = 0x6400
	vmcsExitLinearAddr  uint32 = 0x640a
	vmcsGuestCR0        uint32 = 0x6800
	vmcsGuestCR4        uint32 = 0x6804
	vmcsGuestESBase     uint32 = 0x6806
	vmcsGuestCSBase     uint32 = 0x6808
	vmcsGuestSSBase     uint32 = 0x680a
	vmcsGuestDSBase     uint32 = 0x680c
	vmcsGuestLDTRBase   uint32 = 0x6812
	vmcsGuestTRBase     uint32 = 0x6814
	vmcsGuestGDTRBase   uint32 = 0x6816
	vmcsGuestIDTRBase   uint32 = 0x6818
	vmcsGuestDR7        uint32 = 0x681a
	vmcsGuestRFLAGS     uint32 = 0x6820
	vmcsGuestPendingDbg uint32 = 0x6822
	vmcsGuestSysenterSP uint32 = 0x6824
	vmcsGuestSysenterIP uint32 = 0x6826
)

// VMX control bits (hv_arch_vmx.h).
const (
	cpuBasedHLT        = 1 << 7
	cpuBasedSecondary  = 1 << 31
	entryIA32eGuest    = 1 << 9
	entryLoadEFER      = 1 << 15
	entryIntrValid     = 1 << 31
	entryIntrTypeHWExc = 3 << 8
	cr0PE              = 1 << 0
	cr0MP              = 1 << 1
	cr0ET              = 1 << 4
	cr0NE              = 1 << 5
	cr0WP              = 1 << 16
	cr0PG              = 1 << 31
	cr4PAE             = 1 << 5
	cr4OSFXSR          = 1 << 9
	cr4OSXMMEXCPT      = 1 << 10
	cr4VMXE            = 1 << 13
	cr4OSXSAVE         = 1 << 18
	eferSCE            = 1 << 0
	eferLME            = 1 << 8
	eferLMA            = 1 << 10
	eferNXE            = 1 << 11
	rflagsReserved     = 1 << 1
	rflagsIF           = 1 << 9
	arCodeKernel64     = 0xa09b  // Accessed execute/read code, S, P, L, G.
	arDataKernel       = 0xc093  // Accessed read/write data, S, P, D/B, G.
	arUnusable         = 0x10000 // The unusable bit of the access-rights field.
	arBusyTSS64        = 0x8b    // Busy 64-bit TSS, P.
	segLimitFlat       = 0xffffffff
	tssSelector        = 0x38 // Any index with TI=0: no GDT lookup happens at entry.
)

// x86 user RFLAGS bits that the Sentry may set: CF PF AF ZF SF TF DF OF NT AC ID.
const x86UserFlagsMask = 0x244dd5

// x86 FMASK: SYSCALL clears TF IF DF NT AC in the stub.
const x86SyscallFlagMask = 0x44700

// preemptSlice bounds a run. hv_vcpu_interrupt is not documented to persist
// across a vCPU that has not entered the guest yet, so a lost interrupt waits
// at most one slice. The slice also bounds a stale TLB after a lost kick.
const preemptSlice = 10 * time.Millisecond

type syncState struct {
	pt  uint64 // GuestPageTable.id; zero means unknown.
	tlb uint64
}

// archWorker is the x86 state that only the worker thread touches.
type archWorker struct {
	cr3      uint64
	cr3Valid bool
	// needsReset means the vCPU does not wait in kernel mode at the reload
	// routine: CS, SS, RFLAGS, RIP and RSP need a reset before the next entry.
	needsReset bool
	// synced is the TLB state of the last invalidation. entry is the state of
	// the current entry.
	synced, entry syncState
	// noTimer is set when the processor lacks the VMX preemption timer.
	noTimer bool
	// ran records that this Switch entered the guest, so the XSAVE image of
	// the vCPU is newer than the one in the Context.
	ran bool
	// injected means the host injected the bounce exception and the guest has
	// not reached the stub yet. The state of the guest is still in the vCPU, so
	// the loop must not return before the stub spills it.
	injected bool
}

// kernelCS and friends as VMCS values.
var (
	codeVA   = uint64(kernelCodeVA)
	reloadVA = codeVA + x86CodeReload
)

func cap2ctrl(capability, ctrl uint64) uint64 {
	return (ctrl | capability&0xffffffff) & (capability >> 32)
}

// initVCPU creates the vCPU on the calling thread and writes the VMCS and MSR
// state that never changes between runs.
func (w *vcpuWorker) initVCPU() error {
	id, _, err := hvVCPUCreate()
	if err != nil {
		return err
	}
	w.id = id
	if err := w.configure(); err != nil {
		w.destroyed.Store(true)
		return errors.Join(err, hvVCPUDestroy(id))
	}
	return nil
}

func (w *vcpuWorker) writeVMCS(pairs ...[2]uint64) error {
	for _, p := range pairs {
		if err := hvWriteVMCS(w.id, uint32(p[0]), p[1]); err != nil {
			return fmt.Errorf("vmcs field %#x: %w", p[0], err)
		}
	}
	return nil
}

func (w *vcpuWorker) configure() error {
	// Execution controls. The framework adds the controls it needs itself:
	// EPT, unrestricted guest and VPID.
	var ctl [4]uint64
	for i, c := range []uint32{hvVMXCapPinBased, hvVMXCapProcBased, hvVMXCapProcBased2, hvVMXCapEntry} {
		v, err := hvReadCapability(c)
		if err != nil {
			return err
		}
		ctl[i] = v
	}
	entry := cap2ctrl(ctl[3], entryIA32eGuest|entryLoadEFER)
	if entry&entryIA32eGuest == 0 {
		return errors.New("hvf: the processor cannot enter a 64-bit guest")
	}
	xcr0 := hostXCR0()
	cr0 := uint64(cr0PG | cr0WP | cr0NE | cr0ET | cr0MP | cr0PE)
	cr4 := uint64(cr4PAE | cr4OSFXSR | cr4OSXMMEXCPT | cr4VMXE)
	if xcr0 != 0 {
		cr4 |= cr4OSXSAVE
	}
	err := w.writeVMCS(
		[2]uint64{uint64(vmcsCtrlPin), cap2ctrl(ctl[0], 0)},
		[2]uint64{uint64(vmcsCtrlCPU), cap2ctrl(ctl[1], cpuBasedHLT|cpuBasedSecondary)},
		[2]uint64{uint64(vmcsCtrlCPU2), cap2ctrl(ctl[2], 0)},
		[2]uint64{uint64(vmcsCtrlEntry), entry},
		[2]uint64{uint64(vmcsCtrlExcBitmap), 0},
		[2]uint64{uint64(vmcsCtrlPFMask), 0},
		[2]uint64{uint64(vmcsCtrlPFMatch), 0},
		// The guest sees CR0 and CR4 as written. VMXE stays hidden.
		[2]uint64{uint64(vmcsGuestCR0), cr0},
		[2]uint64{uint64(vmcsCtrlCR0Mask), cr0PE | cr0PG | cr0NE},
		[2]uint64{uint64(vmcsCtrlCR0Shadow), cr0},
		[2]uint64{uint64(vmcsGuestCR4), cr4},
		[2]uint64{uint64(vmcsCtrlCR4Mask), cr4VMXE},
		[2]uint64{uint64(vmcsCtrlCR4Shadow), cr4 &^ cr4VMXE},
		[2]uint64{uint64(vmcsGuestEFER), eferSCE | eferLME | eferLMA | eferNXE},
		// Descriptor tables and the task register.
		[2]uint64{uint64(vmcsGuestGDTRBase), kernelGDTVA},
		[2]uint64{uint64(vmcsGuestGDTRLimit), uint64(x86GDTLimit)},
		[2]uint64{uint64(vmcsGuestIDTRBase), kernelIDTVA},
		[2]uint64{uint64(vmcsGuestIDTRLimit), x86IDTLimit},
		[2]uint64{uint64(vmcsGuestTR), tssSelector},
		[2]uint64{uint64(vmcsGuestTRBase), w.comm.va + uint64(x86OffTSS)},
		[2]uint64{uint64(vmcsGuestTRLimit), x86TSSLimit},
		[2]uint64{uint64(vmcsGuestTRAR), arBusyTSS64},
		[2]uint64{uint64(vmcsGuestLDTR), 0},
		[2]uint64{uint64(vmcsGuestLDTRBase), 0},
		[2]uint64{uint64(vmcsGuestLDTRLimit), 0},
		[2]uint64{uint64(vmcsGuestLDTRAR), arUnusable},
		// DS, ES, FS and GS are unusable null segments: 64-bit mode ignores them
		// except for the FS and GS bases, which MSRs carry.
		[2]uint64{uint64(vmcsGuestDS), 0}, [2]uint64{uint64(vmcsGuestDSBase), 0},
		[2]uint64{uint64(vmcsGuestDSLimit), segLimitFlat}, [2]uint64{uint64(vmcsGuestDSAR), arUnusable},
		[2]uint64{uint64(vmcsGuestES), 0}, [2]uint64{uint64(vmcsGuestESBase), 0},
		[2]uint64{uint64(vmcsGuestESLimit), segLimitFlat}, [2]uint64{uint64(vmcsGuestESAR), arUnusable},
		[2]uint64{uint64(vmcsGuestFS), 0}, [2]uint64{uint64(vmcsGuestFSLimit), segLimitFlat},
		[2]uint64{uint64(vmcsGuestFSAR), arUnusable},
		[2]uint64{uint64(vmcsGuestGS), 0}, [2]uint64{uint64(vmcsGuestGSLimit), segLimitFlat},
		[2]uint64{uint64(vmcsGuestGSAR), arUnusable},
		[2]uint64{uint64(vmcsGuestDR7), 0x400},
		[2]uint64{uint64(vmcsGuestInterrupt), 0},
		[2]uint64{uint64(vmcsGuestActivity), 0},
		[2]uint64{uint64(vmcsGuestPendingDbg), 0},
		[2]uint64{uint64(vmcsLinkPointer), ^uint64(0)},
		[2]uint64{uint64(vmcsGuestSysenterCS), 0},
		[2]uint64{uint64(vmcsGuestSysenterSP), 0},
		[2]uint64{uint64(vmcsGuestSysenterIP), 0},
	)
	if err != nil {
		return err
	}
	if xcr0 != 0 {
		if err := hvWriteRegister(w.id, hvX86XCR0, xcr0); err != nil {
			return err
		}
	}
	// The guest runs SYSCALL, SWAPGS and the segment base MSRs without exits.
	for _, msr := range []uint32{msrSTAR, msrLSTAR, msrCSTAR, msrFMASK, msrFSBase, msrGSBase, msrKernelGS, msrTSCAux,
		msrSysenterCS, msrSysenterESP, msrSysenterEIP, msrTSC} {
		if err := hvEnableNativeMSR(w.id, msr); err != nil {
			return err
		}
	}
	for _, m := range []struct {
		msr uint32
		val uint64
	}{
		{msrSTAR, x86UserCS32<<48 | x86KernelCS<<32},
		{msrLSTAR, codeVA + x86CodeSyscall},
		{msrCSTAR, 0},
		{msrFMASK, x86SyscallFlagMask},
		{msrTSCAux, 0},
		{msrSysenterCS, 0},
		{msrSysenterESP, 0},
		{msrSysenterEIP, 0},
	} {
		if err := hvWriteMSR(w.id, m.msr, m.val); err != nil {
			return err
		}
	}
	w.needsReset = true
	return nil
}

// resetKernelState puts the vCPU into kernel mode at the reload routine: the
// state it has after every stub exit.
func (w *vcpuWorker) resetKernelState() error {
	pairs := [][2]uint64{
		{uint64(vmcsGuestCS), x86KernelCS}, {uint64(vmcsGuestCSBase), 0},
		{uint64(vmcsGuestCSLimit), segLimitFlat}, {uint64(vmcsGuestCSAR), arCodeKernel64},
		{uint64(vmcsGuestSS), x86KernelSS}, {uint64(vmcsGuestSSBase), 0},
		{uint64(vmcsGuestSSLimit), segLimitFlat}, {uint64(vmcsGuestSSAR), arDataKernel},
		{uint64(vmcsGuestRFLAGS), rflagsReserved},
	}
	if err := w.writeVMCS(pairs...); err != nil {
		return err
	}
	w.needsReset = false
	return nil
}

func (w *vcpuWorker) invalidateState() {
	w.needsReset = true
	w.cr3Valid = false
	w.synced = syncState{}
}

// comm and stack views of the worker.
func (w *vcpuWorker) stackFrame() []byte { return w.comm.stack }

// loadContext copies the Sentry thread state into the CommPage and the
// interrupt frame, and the XSAVE image into the vCPU.
func (w *vcpuWorker) loadContext(ac *arch.Context64) error {
	r := &ac.StateData().Regs
	c := w.comm.view
	c.Regs = [16]uint64{
		r.Rax, r.Rcx, r.Rdx, r.Rbx, 0, r.Rbp, r.Rsi, r.Rdi,
		r.R8, r.R9, r.R10, r.R11, r.R12, r.R13, r.R14, r.R15,
	}
	cs := x86UserCS64
	if r.Cs == x86UserCS32 {
		cs = x86UserCS32
	}
	f := w.stackFrame()
	binary.LittleEndian.PutUint64(f[x86FrameVector:], 0)
	binary.LittleEndian.PutUint64(f[x86FrameErrCode:], 0)
	binary.LittleEndian.PutUint64(f[x86FrameRIP:], r.Rip)
	binary.LittleEndian.PutUint64(f[x86FrameCS:], cs)
	binary.LittleEndian.PutUint64(f[x86FrameRFLAGS:], r.Eflags&x86UserFlagsMask|rflagsReserved|rflagsIF)
	binary.LittleEndian.PutUint64(f[x86FrameRSP:], r.Rsp)
	binary.LittleEndian.PutUint64(f[x86FrameSS:], x86UserSS)
	if err := hvWriteFPState(w.id, *ac.FloatingPointData()); err != nil {
		return err
	}
	// The kernel GS base is active while the stub runs: SWAPGS at the end of the
	// reload routine exchanges it with the user GS base that KERNEL_GS_BASE
	// holds. FS needs no exchange.
	for _, m := range []struct {
		msr uint32
		val uint64
	}{
		{msrFSBase, r.Fs_base},
		{msrKernelGS, r.Gs_base},
		{msrGSBase, w.comm.va},
	} {
		if err := hvWriteMSR(w.id, m.msr, m.val); err != nil {
			return err
		}
	}
	return nil
}

// storeFromStub copies the state that the stub spilled into ac.
func (w *vcpuWorker) storeFromStub(ac *arch.Context64) error {
	r := &ac.StateData().Regs
	c := w.comm.view
	f := w.stackFrame()
	r.Rax, r.Rcx, r.Rdx, r.Rbx = c.Regs[0], c.Regs[1], c.Regs[2], c.Regs[3]
	r.Rbp, r.Rsi, r.Rdi = c.Regs[5], c.Regs[6], c.Regs[7]
	r.R8, r.R9, r.R10, r.R11 = c.Regs[8], c.Regs[9], c.Regs[10], c.Regs[11]
	r.R12, r.R13, r.R14, r.R15 = c.Regs[12], c.Regs[13], c.Regs[14], c.Regs[15]
	r.Rip = binary.LittleEndian.Uint64(f[x86FrameRIP:])
	r.Cs = binary.LittleEndian.Uint64(f[x86FrameCS:])
	r.Eflags = binary.LittleEndian.Uint64(f[x86FrameRFLAGS:])
	r.Rsp = binary.LittleEndian.Uint64(f[x86FrameRSP:])
	r.Ss = binary.LittleEndian.Uint64(f[x86FrameSS:])
	fs, err := hvReadMSR(w.id, msrFSBase)
	if err != nil {
		return err
	}
	gs, err := hvReadMSR(w.id, msrKernelGS)
	if err != nil {
		return err
	}
	r.Fs_base, r.Gs_base = fs, gs
	return nil
}

// captureUser reads the user-mode register state of a vCPU that stopped in
// user mode, into ac. It is the cold path.
func (w *vcpuWorker) captureUser(ac *arch.Context64) error {
	r := &ac.StateData().Regs
	for i, dst := range []*uint64{
		&r.Rax, &r.Rcx, &r.Rdx, &r.Rbx, &r.Rsp, &r.Rbp, &r.Rsi, &r.Rdi,
		&r.R8, &r.R9, &r.R10, &r.R11, &r.R12, &r.R13, &r.R14, &r.R15,
	} {
		v, err := hvReadRegister(w.id, hvX86GPR[i])
		if err != nil {
			return err
		}
		*dst = v
	}
	for _, f := range []struct {
		reg uint32
		dst *uint64
	}{
		{hvX86RIP, &r.Rip}, {hvX86RFLAGS, &r.Eflags}, {hvX86CS, &r.Cs}, {hvX86SS, &r.Ss},
	} {
		v, err := hvReadRegister(w.id, f.reg)
		if err != nil {
			return err
		}
		*f.dst = v
	}
	var err error
	if r.Fs_base, err = hvReadMSR(w.id, msrFSBase); err != nil {
		return err
	}
	// User mode runs with the user GS base active.
	if r.Gs_base, err = hvReadMSR(w.id, msrGSBase); err != nil {
		return err
	}
	return hvReadFPState(w.id, *ac.FloatingPointData())
}

// runSwitch executes one Switch request on the worker thread.
func (w *vcpuWorker) runSwitch(r *switchReq) (*linux.SignalInfo, hostarch.AccessType, error) {
	c, as, ac := r.c, r.as, r.ac
	pt := as.pt
	w.curPT.Store(pt)
	defer w.curPT.Store(nil)
	w.ran = false

	if err := w.begin(pt, ac); err != nil {
		return nil, hostarch.NoAccess, err
	}
	info, at, err := w.runLoop(r, c, pt, ac)
	if w.ran && !w.needsReset {
		// A stub exit or an aborted entry left the vCPU in kernel mode, and the
		// guest changed its FP state since the load.
		if rerr := hvReadFPState(w.id, *ac.FloatingPointData()); rerr != nil {
			w.invalidateState()
			return nil, hostarch.NoAccess, errors.Join(err, rerr)
		}
	}
	return info, at, err
}

// begin prepares the vCPU for one Switch: address space, user state, and the
// kernel-mode entry point.
func (w *vcpuWorker) begin(pt *GuestPageTable, ac *arch.Context64) error {
	w.injected = false
	if pt.dead.Load() {
		return errPageTableReleased
	}
	if err := w.loadContext(ac); err != nil {
		w.invalidateState()
		return err
	}
	if w.needsReset {
		if err := w.resetKernelState(); err != nil {
			w.invalidateState()
			return err
		}
	}
	if root := pt.RootIPA(); !w.cr3Valid || w.cr3 != root {
		if err := hvWriteRegister(w.id, hvX86CR3, root); err != nil {
			w.invalidateState()
			return err
		}
		w.cr3, w.cr3Valid = root, true
	}
	for _, reg := range [][2]uint64{
		{uint64(hvX86RIP), reloadVA},
		{uint64(hvX86RSP), w.comm.frameSlotVA()},
		{uint64(hvX86RFLAGS), rflagsReserved},
	} {
		if err := hvWriteRegister(w.id, uint32(reg[0]), reg[1]); err != nil {
			w.invalidateState()
			return err
		}
	}
	return nil
}

// syncTLB invalidates the vCPU TLB when the table changed since the last
// invalidation, and records the generation that the entry covers.
func (w *vcpuWorker) syncTLB(pt *GuestPageTable) error {
	tlb := pt.tlbGen.Load()
	if w.synced.pt != pt.id || w.synced.tlb != tlb {
		if err := hvInvalidateTLB(w.id); err != nil {
			w.invalidateState()
			return err
		}
		w.synced = syncState{pt: pt.id, tlb: tlb}
	}
	w.entry = w.synced
	return nil
}

// beginRun announces the entry to quiesce. It reports false when the table
// changed after syncTLB.
func (w *vcpuWorker) beginRun(pt *GuestPageTable) bool {
	w.enterTLB.Store(w.entry.tlb)
	w.inGuest.Store(true)
	if pt.tlbGen.Load() != w.entry.tlb || pt.dead.Load() {
		w.inGuest.Store(false)
		return false
	}
	return true
}

// runLoop enters the guest until an exit needs the Sentry.
func (w *vcpuWorker) runLoop(r *switchReq, c *Context, pt *GuestPageTable, ac *arch.Context64) (*linux.SignalInfo, hostarch.AccessType, error) {
	for {
		if w.quit.Load() {
			return nil, hostarch.NoAccess, errPlatformClosed
		}
		if !w.injected && c.interrupted.CompareAndSwap(true, false) {
			return nil, hostarch.NoAccess, platform.ErrContextInterrupt
		}
		if pt.dead.Load() {
			return nil, hostarch.NoAccess, errPageTableReleased
		}
		if err := w.syncTLB(pt); err != nil {
			return nil, hostarch.NoAccess, err
		}
		if !w.beginRun(pt) {
			continue
		}
		runErr := w.enterGuest()
		w.inGuest.Store(false)
		w.ran = true
		if runErr != nil {
			w.invalidateState()
			return nil, hostarch.NoAccess, runErr
		}
		if e := w.cancelErr.Swap(nil); e != nil {
			w.invalidateState()
			return nil, hostarch.NoAccess, fmt.Errorf("hvf: a cancellation of the vCPU failed: %w", *e)
		}
		done, info, at, err := w.dispatchExit(r, c, pt, ac)
		if done {
			return info, at, err
		}
	}
}

// enterGuest enters the guest. It uses the preemption timer to bound the run, and
// falls back to an unbounded run on a processor without the timer.
func (w *vcpuWorker) enterGuest() error {
	if w.noTimer {
		return hvVCPURun(w.id)
	}
	now, err := machAbsoluteTime()
	if err != nil {
		return err
	}
	slice, err := machTicks(uint64(preemptSlice))
	if err != nil {
		return err
	}
	err = hvVCPURunUntil(w.id, now+slice)
	if code, ok := hvCode(err); ok && code == hvErrUnsupport {
		w.noTimer = true
		return hvVCPURun(w.id)
	}
	return err
}

func (w *vcpuWorker) exitReason() (uint64, error) {
	v, err := hvReadVMCS(w.id, vmcsExitReason)
	if err != nil {
		return 0, err
	}
	if v&vmxExitEntryFailureBit != 0 {
		return 0, fmt.Errorf("hvf: VM entry failed (exit reason %#x): the guest state is invalid", v)
	}
	return v & vmxExitReasonMask, nil
}

// dispatchExit decodes one exit. It reports done=false when the loop must
// enter the guest again.
func (w *vcpuWorker) dispatchExit(r *switchReq, c *Context, pt *GuestPageTable, ac *arch.Context64) (bool, *linux.SignalInfo, hostarch.AccessType, error) {
	reason, err := w.exitReason()
	if err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	switch reason {
	case vmxExitHLT:
		return w.onHLT(c, pt, ac)
	case vmxExitExternalInterrupt, vmxExitPreemptionTimer:
		return w.onCancel(c, pt)
	case vmxExitCPUID:
		return w.onCPUID(r, ac)
	case vmxExitVMCALL:
		return w.onUserSignal(ac, signalAction(linux.SIGILL, sigIllOpn, 0, hostarch.NoAccess), true)
	case vmxExitEPTViolation:
		return w.onEPTViolation(ac)
	default:
		w.invalidateState()
		q, _ := hvReadVMCS(w.id, vmcsExitQual)
		return true, nil, hostarch.NoAccess, fmt.Errorf("hvf: unexpected VM exit reason %d (qualification %#x)", reason, q)
	}
}

// userMode reports whether the guest runs in user mode, from the CS selector.
func (w *vcpuWorker) userMode() (bool, error) {
	cs, err := hvReadRegister(w.id, hvX86CS)
	if err != nil {
		return false, err
	}
	return cs&3 == 3, nil
}

// onCancel resumes after a cancellation unless the Sentry needs the vCPU.
func (w *vcpuWorker) onCancel(c *Context, pt *GuestPageTable) (bool, *linux.SignalInfo, hostarch.AccessType, error) {
	pending := c.interrupted.Load()
	quit := w.quit.Load()
	if !pending && !quit {
		// A timer slice or a stale cancellation. The next syncTLB covers a
		// stale TLB; resume where the vCPU stopped.
		return false, nil, hostarch.NoAccess, nil
	}
	user, err := w.userMode()
	if err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	if user {
		// Take the vCPU out of user mode through the IDT: inject #VE. The stub
		// spills the registers and executes HLT, and onHLT reports the bounce.
		if err := w.writeVMCS(
			[2]uint64{uint64(vmcsCtrlEntryIRQ), entryIntrValid | entryIntrTypeHWExc | x86VecBounce},
		); err != nil {
			w.invalidateState()
			return true, nil, hostarch.NoAccess, err
		}
		w.injected = true
		return false, nil, hostarch.NoAccess, nil
	}
	rip, err := hvReadRegister(w.id, hvX86RIP)
	if err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	if rip >= codeVA && rip < reloadVA {
		// The stub holds guest state in registers. Let it reach its HLT.
		return false, nil, hostarch.NoAccess, nil
	}
	// The reload routine only reads the CommPage and the frame, which are
	// complete. Restart it later and leave the guest.
	w.needsReset = true
	switch {
	case quit:
		return true, nil, hostarch.NoAccess, errPlatformClosed
	case c.interrupted.CompareAndSwap(true, false):
		return true, nil, hostarch.NoAccess, platform.ErrContextInterrupt
	}
	return false, nil, hostarch.NoAccess, nil
}

// onHLT decodes the HLT that ends the stub spill routine.
func (w *vcpuWorker) onHLT(c *Context, pt *GuestPageTable, ac *arch.Context64) (bool, *linux.SignalInfo, hostarch.AccessType, error) {
	rip, err := hvReadRegister(w.id, hvX86RIP)
	if err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	if rip != codeVA+uint64(w.vm.kernel.hltOffset) {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, fmt.Errorf("hvf: HLT exit at %#x outside the stub", rip)
	}
	f := w.stackFrame()
	vec := binary.LittleEndian.Uint64(f[x86FrameVector:])
	errCode := binary.LittleEndian.Uint64(f[x86FrameErrCode:])
	userRIP := binary.LittleEndian.Uint64(f[x86FrameRIP:])
	cs := binary.LittleEndian.Uint64(f[x86FrameCS:])
	var dr6 uint64
	if vec == x86VecDebug {
		if dr6, err = hvReadRegister(w.id, hvX86DR6); err != nil {
			w.invalidateState()
			return true, nil, hostarch.NoAccess, err
		}
	}
	w.injected = false
	act := decodeX86StubExit(vec, errCode, w.comm.view.CR2, userRIP, cs, dr6)
	if act.kind == exitInternal {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, act.err
	}
	if err := w.storeFromStub(ac); err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	switch act.kind {
	case exitSyscall:
		ac.StateData().Regs.Orig_rax = ac.StateData().Regs.Rax
		return true, nil, hostarch.NoAccess, nil
	case exitSignal:
		return true, act.info, act.at, platform.ErrContextSignal
	case exitBounce:
		// The injection ended a user-mode run and ac holds the complete state.
		switch {
		case w.quit.Load():
			return true, nil, hostarch.NoAccess, errPlatformClosed
		case c.interrupted.CompareAndSwap(true, false):
			return true, nil, hostarch.NoAccess, platform.ErrContextInterrupt
		}
		// Nothing asked for the stop any more: re-enter user mode from ac.
		return false, nil, hostarch.NoAccess, w.begin(pt, ac)
	}
	w.invalidateState()
	return true, nil, hostarch.NoAccess, fmt.Errorf("hvf: unhandled stub exit kind %d", act.kind)
}

// onCPUID emulates a CPUID that the guest executed. The Sentry owns the feature
// set that the guest sees, so the platform helper performs the emulation.
func (w *vcpuWorker) onCPUID(r *switchReq, ac *arch.Context64) (bool, *linux.SignalInfo, hostarch.AccessType, error) {
	user, err := w.userMode()
	if err != nil || !user {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, errors.Join(err, errors.New("hvf: CPUID exit outside user mode"))
	}
	if err := w.captureUser(ac); err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	if platform.TryCPUIDEmulate(r.ctx, r.mm, ac) {
		regs := &ac.StateData().Regs
		for _, wr := range []struct {
			reg uint32
			val uint64
		}{
			{hvX86RAX, regs.Rax}, {hvX86RBX, regs.Rbx}, {hvX86RCX, regs.Rcx}, {hvX86RDX, regs.Rdx}, {hvX86RIP, regs.Rip},
		} {
			if err := hvWriteRegister(w.id, wr.reg, wr.val); err != nil {
				w.invalidateState()
				return true, nil, hostarch.NoAccess, err
			}
		}
		return false, nil, hostarch.NoAccess, nil
	}
	// Not a CPUID the Sentry can emulate: report it as a general protection fault.
	w.needsReset = true
	act := signalAction(linux.SIGSEGV, siKernel, ac.StateData().Regs.Rip, hostarch.NoAccess)
	return true, act.info, act.at, platform.ErrContextSignal
}

// onUserSignal reports a signal for a direct exit from user mode.
func (w *vcpuWorker) onUserSignal(ac *arch.Context64, act exitAction, atRIP bool) (bool, *linux.SignalInfo, hostarch.AccessType, error) {
	user, err := w.userMode()
	if err != nil || !user {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, errors.Join(err, errors.New("hvf: exit outside user mode"))
	}
	if err := w.captureUser(ac); err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	w.needsReset = true
	if atRIP {
		act.info.SetAddr(ac.StateData().Regs.Rip)
	}
	return true, act.info, act.at, platform.ErrContextSignal
}

// onEPTViolation reports a guest access to a page without a host mapping.
func (w *vcpuWorker) onEPTViolation(ac *arch.Context64) (bool, *linux.SignalInfo, hostarch.AccessType, error) {
	qual, err := hvReadVMCS(w.id, vmcsExitQual)
	if err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	lin, err := hvReadVMCS(w.id, vmcsExitLinearAddr)
	if err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	return w.onUserSignal(ac, decodeEPTViolation(qual, lin), false)
}
