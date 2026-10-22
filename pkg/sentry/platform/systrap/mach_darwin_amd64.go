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

//go:build darwin && amd64

package systrap

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// machPort is a Mach port name in the Sentry's port namespace.
type machPort uint32

// kernReturn is a Mach kern_return_t.
type kernReturn int32

const (
	kernSuccess              kernReturn = 0
	kernInvalidAddress       kernReturn = 1
	kernProtectionFailure    kernReturn = 2
	kernNoSpace              kernReturn = 3
	kernInvalidArgument      kernReturn = 4
	kernFailure              kernReturn = 5
	kernInvalidName          kernReturn = 15
	kernTerminated           kernReturn = 49
	machSendInvalidDest      kernReturn = 0x10000003
	machRcvTimedOut          kernReturn = 0x10004003
	machSendTimedOut         kernReturn = 0x10000004
	machRcvPortDied          kernReturn = 0x10004009
	machRcvTooLarge          kernReturn = 0x10004004
	machRcvInvalidName       kernReturn = 0x10004002
	machRcvPortChanged       kernReturn = 0x1000400b
	machMsgInvalidKernArg    kernReturn = 0x1000000a
	machSendInterrupted      kernReturn = 0x10000007
	machRcvInterrupted       kernReturn = 0x10004005
	kernAborted              kernReturn = 14
	kernMemoryError          kernReturn = 10
	kernResourceShortage     kernReturn = 6
	kernNoAccess             kernReturn = 8
	kernInvalidRight         kernReturn = 17
	kernInvalidCapability    kernReturn = 20
	kernDenied               kernReturn = 53
	kernCodesignError        kernReturn = 50
	machPortNull             machPort   = 0
	machPortRightReceive                = 1
	machMsgTypeMakeSend                 = 20
	machMsgTypeMakeSendOnce             = 21
	machMsgTypeCopySend                 = 19
	machSendMsg                         = 0x1
	machRcvMsg                          = 0x2
	machSendTimeout                     = 0x10
	machRcvTimeout                      = 0x100
	machNotifyDeadName                  = 72
	machMsgComplex                      = 0x80000000
	vmFlagsFixed                        = 0x0
	vmFlagsAnywhere                     = 0x1
	vmFlagsOverwrite                    = 0x4000
	vmInheritNone                       = 2
	vmProtRead                          = 1
	vmProtWrite                         = 2
	vmProtExecute                       = 4
	excMaskResource                     = 1 << 11
	exceptionDefault                    = 1
	threadStateNone                     = 13
	excTypesCount                       = 14
	taskBootstrapPort                   = 4
	machPortDead             machPort   = 0xffffffff
	posixSpawnSetPgroup                 = 0x2
	posixSpawnSetSigDef                 = 0x4
	posixSpawnSetSigMask                = 0x8
	posixSpawnCloexecDefault            = 0x4000
	cpuTypeX86_64                       = 0x01000007
)

// MachError reports a failed Mach call.
type MachError struct {
	Op   string
	Code kernReturn
}

// Error implements error.
func (e *MachError) Error() string {
	return fmt.Sprintf("%s: %s (kern_return_t %#x)", e.Op, e.Code, uint32(e.Code))
}

// String names the common return codes.
func (k kernReturn) String() string {
	switch k {
	case kernSuccess:
		return "success"
	case kernInvalidAddress:
		return "invalid address"
	case kernProtectionFailure:
		return "protection failure"
	case kernNoSpace:
		return "no space"
	case kernInvalidArgument:
		return "invalid argument"
	case kernFailure:
		return "failure"
	case kernResourceShortage:
		return "resource shortage"
	case kernNoAccess:
		return "no access"
	case kernInvalidName:
		return "invalid name"
	case kernInvalidRight:
		return "invalid right"
	case kernTerminated:
		return "terminated"
	case kernDenied:
		return "denied"
	case machSendInvalidDest:
		return "send invalid destination (peer is gone)"
	case machRcvTimedOut:
		return "receive timed out"
	case machRcvPortDied:
		return "receive port died"
	}
	return "unknown"
}

// IsDead reports whether err means that the remote task or port no longer exists.
func isDeadTaskError(err error) bool {
	var me *MachError
	if !errors.As(err, &me) {
		return false
	}
	switch me.Code {
	case machSendInvalidDest, kernTerminated, kernInvalidArgument, kernInvalidName, kernInvalidRight, machRcvPortDied:
		return true
	}
	return false
}

func kr(op string, r uintptr) error {
	if c := kernReturn(int32(r)); c != kernSuccess {
		return &MachError{Op: op, Code: c}
	}
	return nil
}

// machCalls holds the resolved libSystem entry points.
var machCalls struct {
	vmRemap, vmProtect, vmDeallocate, vmAllocate                libcFunc
	portAllocate, portInsertRight, portDeallocate, portDestroy  libcFunc
	portRequestNotification, portModRefs, msg                   libcFunc
	threadSuspend, threadResume, threadTerminate, taskTerminate libcFunc
	spawn, spawnattrInit, spawnattrDestroy, spawnattrSetFlags   libcFunc
	spawnattrSetSigDefault, spawnattrSetSigMask                 libcFunc
	spawnattrSetPgroup, spawnattrSetBinPref                     libcFunc
	fileActionsInit, fileActionsAddDup2                         libcFunc
	fileActionsAddClose, fileActionsDestroy                     libcFunc
	ulockWait, ulockWake                                        libcFunc
	taskSetExceptionPorts, taskGetExceptionPorts                libcFunc
	taskGetSpecialPort, bootstrapRegister                       libcFunc
	vmRegion                                                    libcFunc
}

func init() {
	c := &machCalls
	c.vmRemap = mustResolve("mach_vm_remap")
	c.vmProtect = mustResolve("mach_vm_protect")
	c.vmDeallocate = mustResolve("mach_vm_deallocate")
	c.vmAllocate = mustResolve("mach_vm_allocate")
	c.portAllocate = mustResolve("mach_port_allocate")
	c.portInsertRight = mustResolve("mach_port_insert_right")
	c.portDeallocate = mustResolve("mach_port_deallocate")
	c.portDestroy = mustResolve("mach_port_destroy")
	c.portRequestNotification = mustResolve("mach_port_request_notification")
	c.portModRefs = mustResolve("mach_port_mod_refs")
	c.msg = mustResolve("mach_msg")
	c.threadSuspend = mustResolve("thread_suspend")
	c.threadResume = mustResolve("thread_resume")
	c.threadTerminate = mustResolve("thread_terminate")
	c.taskTerminate = mustResolve("task_terminate")
	c.spawn = mustResolve("posix_spawn")
	c.spawnattrInit = mustResolve("posix_spawnattr_init")
	c.spawnattrDestroy = mustResolve("posix_spawnattr_destroy")
	c.spawnattrSetFlags = mustResolve("posix_spawnattr_setflags")
	c.spawnattrSetSigDefault = mustResolve("posix_spawnattr_setsigdefault")
	c.spawnattrSetSigMask = mustResolve("posix_spawnattr_setsigmask")
	c.spawnattrSetPgroup = mustResolve("posix_spawnattr_setpgroup")
	c.spawnattrSetBinPref = mustResolve("posix_spawnattr_setbinpref_np")
	c.fileActionsInit = mustResolve("posix_spawn_file_actions_init")
	c.fileActionsAddDup2 = mustResolve("posix_spawn_file_actions_adddup2")
	c.fileActionsAddClose = mustResolve("posix_spawn_file_actions_addclose")
	c.fileActionsDestroy = mustResolve("posix_spawn_file_actions_destroy")
	c.ulockWait = mustResolve("__ulock_wait")
	c.ulockWake = mustResolve("__ulock_wake")
	c.taskSetExceptionPorts = mustResolve("task_set_exception_ports")
	c.taskGetExceptionPorts = mustResolve("task_get_exception_ports")
	c.taskGetSpecialPort = mustResolve("task_get_special_port")
	c.bootstrapRegister = mustResolve("bootstrap_register")
	c.vmRegion = mustResolve("mach_vm_region")
}

// vmRemap maps size bytes of srcTask at srcAddr into dstTask at dstAddr and
// replaces any mapping there. The mapping shares the pages with the source.
func vmRemap(dstTask machPort, dstAddr, size uint64, srcTask machPort, srcAddr uint64) error {
	target := dstAddr
	var cur, max int32
	r := machCalls.vmRemap.call(
		uintptr(dstTask), uintptr(unsafe.Pointer(&target)), uintptr(size), 0,
		vmFlagsFixed|vmFlagsOverwrite, uintptr(srcTask), uintptr(srcAddr), 0,
		uintptr(unsafe.Pointer(&cur)), uintptr(unsafe.Pointer(&max)), vmInheritNone)
	runtime.KeepAlive(&target)
	runtime.KeepAlive(&cur)
	runtime.KeepAlive(&max)
	if err := kr("mach_vm_remap", r); err != nil {
		return err
	}
	if target != dstAddr {
		return fmt.Errorf("mach_vm_remap placed the mapping at %#x instead of %#x", target, dstAddr)
	}
	return nil
}

// vmRegionBasicInfo64 is VM_REGION_BASIC_INFO_64 and the size in 32-bit words
// of its vm_region_basic_info_data_64_t.
const (
	vmRegionBasicInfo64      = 9
	vmRegionBasicInfoWords64 = 9
)

// vmRegion returns the first mapping of task that ends above addr. It reports
// ok as false when no mapping lies at or above addr.
func vmRegion(task machPort, addr uint64) (start, size uint64, ok bool, err error) {
	var info [16]int32
	count := uint32(vmRegionBasicInfoWords64)
	var object uint32
	start = addr
	r := machCalls.vmRegion.call(
		uintptr(task), uintptr(unsafe.Pointer(&start)), uintptr(unsafe.Pointer(&size)),
		vmRegionBasicInfo64, uintptr(unsafe.Pointer(&info[0])),
		uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&object)))
	runtime.KeepAlive(&start)
	runtime.KeepAlive(&size)
	runtime.KeepAlive(&info)
	runtime.KeepAlive(&count)
	runtime.KeepAlive(&object)
	if kernReturn(int32(r)) == kernInvalidAddress {
		return 0, 0, false, nil
	}
	if err := kr("mach_vm_region", r); err != nil {
		return 0, 0, false, err
	}
	return start, size, true, nil
}

// vmProtect changes the current or the maximum protection of a range.
func vmProtect(task machPort, addr, size uint64, setMax bool, prot int) error {
	m := uintptr(0)
	if setMax {
		m = 1
	}
	return kr("mach_vm_protect", machCalls.vmProtect.call(uintptr(task), uintptr(addr), uintptr(size), m, uintptr(prot)))
}

// vmDeallocate unmaps a range of a task.
func vmDeallocate(task machPort, addr, size uint64) error {
	return kr("mach_vm_deallocate", machCalls.vmDeallocate.call(uintptr(task), uintptr(addr), uintptr(size)))
}

// vmAllocate maps fresh zero pages at an address chosen by the kernel.
func vmAllocate(task machPort, size uint64) (uint64, error) {
	var addr uint64
	r := machCalls.vmAllocate.call(uintptr(task), uintptr(unsafe.Pointer(&addr)), uintptr(size), vmFlagsAnywhere)
	runtime.KeepAlive(&addr)
	return addr, kr("mach_vm_allocate", r)
}

func portAllocateReceive(task machPort) (machPort, error) {
	var name uint32
	r := machCalls.portAllocate.call(uintptr(task), machPortRightReceive, uintptr(unsafe.Pointer(&name)))
	runtime.KeepAlive(&name)
	return machPort(name), kr("mach_port_allocate", r)
}

func portInsertSendRight(task, name machPort) error {
	return kr("mach_port_insert_right", machCalls.portInsertRight.call(uintptr(task), uintptr(name), uintptr(name), machMsgTypeMakeSend))
}

func portDeallocate(task, name machPort) error {
	return kr("mach_port_deallocate", machCalls.portDeallocate.call(uintptr(task), uintptr(name)))
}

func portDestroy(task, name machPort) error {
	return kr("mach_port_destroy", machCalls.portDestroy.call(uintptr(task), uintptr(name)))
}

// portRequestDeadName asks the kernel to send a dead-name notification for
// name to notify when the port's receiver dies.
func portRequestDeadName(task, name, notify machPort) error {
	var prev uint32
	r := machCalls.portRequestNotification.call(uintptr(task), uintptr(name), machNotifyDeadName, 0,
		uintptr(notify), machMsgTypeMakeSendOnce, uintptr(unsafe.Pointer(&prev)))
	runtime.KeepAlive(&prev)
	if err := kr("mach_port_request_notification", r); err != nil {
		return err
	}
	if prev != 0 {
		// The kernel returns a previous notification right only when another request exists.
		_ = portDeallocate(selfTask(), machPort(prev))
	}
	return nil
}

// machMsgCall wraps mach_msg.
func machMsgCall(msg unsafe.Pointer, option uint32, sendSize, rcvSize uint32, rcvName machPort, timeoutMs uint32) kernReturn {
	r := machCalls.msg.call(uintptr(msg), uintptr(option), uintptr(sendSize), uintptr(rcvSize), uintptr(rcvName), uintptr(timeoutMs), 0)
	return kernReturn(int32(r))
}

// posixErr converts the errno that a posix_spawn family call returns.
// These calls report failure through their return value, not through errno.
func posixErr(op string, r uintptr) error {
	if e := uint32(r); e != 0 {
		return fmt.Errorf("%s: %w", op, syscall.Errno(e))
	}
	return nil
}

// spawnattrPreferX86 limits the binary preference of attr to x86_64. The
// stub image is an x86_64 program that runs translated. The preference makes
// the kernel pick that slice of a universal image even if the Sentry runs natively.
func spawnattrPreferX86(attr *uintptr) error {
	pref := int32(cpuTypeX86_64)
	var out uintptr
	r := machCalls.spawnattrSetBinPref.call(uintptr(unsafe.Pointer(attr)), 1, uintptr(unsafe.Pointer(&pref)), uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(attr)
	runtime.KeepAlive(&pref)
	runtime.KeepAlive(&out)
	return posixErr("posix_spawnattr_setbinpref_np", r)
}

// spawnFileActionsInit prepares an empty file action list for posix_spawn.
// The stub must start with an exact descriptor set, so the Sentry lists each change.
func spawnFileActionsInit(fa *uintptr) error {
	r := machCalls.fileActionsInit.call(uintptr(unsafe.Pointer(fa)))
	runtime.KeepAlive(fa)
	return posixErr("posix_spawn_file_actions_init", r)
}

// spawnFileActionsAddDup2 makes the child see fd as newfd. The stub learns
// its hand-off descriptor at a fixed number this way.
func spawnFileActionsAddDup2(fa *uintptr, fd, newfd int) error {
	r := machCalls.fileActionsAddDup2.call(uintptr(unsafe.Pointer(fa)), uintptr(fd), uintptr(newfd))
	runtime.KeepAlive(fa)
	return posixErr("posix_spawn_file_actions_adddup2", r)
}

// spawnFileActionsAddClose closes fd in the child. It keeps the stub from
// inheriting descriptors that the Sentry leaves open.
func spawnFileActionsAddClose(fa *uintptr, fd int) error {
	r := machCalls.fileActionsAddClose.call(uintptr(unsafe.Pointer(fa)), uintptr(fd))
	runtime.KeepAlive(fa)
	return posixErr("posix_spawn_file_actions_addclose", r)
}

// spawnFileActionsDestroy frees the file action list after posix_spawn.
// The list owns memory in libSystem, so the caller must release it.
func spawnFileActionsDestroy(fa *uintptr) error {
	r := machCalls.fileActionsDestroy.call(uintptr(unsafe.Pointer(fa)))
	runtime.KeepAlive(fa)
	return posixErr("posix_spawn_file_actions_destroy", r)
}

// taskSetExceptionPorts routes the exceptions in mask of task to port. The
// Sentry uses it to learn about a fault in a stub task that no signal handler covers.
func taskSetExceptionPorts(task machPort, mask uint32, port machPort) error {
	r := machCalls.taskSetExceptionPorts.call(uintptr(task), uintptr(mask), uintptr(port), exceptionDefault, threadStateNone)
	return kr("task_set_exception_ports", r)
}

// taskGetExceptionPort returns the send right that task registered for the
// first exception type in mask, or machPortNull when no handler exists. The
// Sentry needs it to learn which port a translated task inherited by default.
// The caller owns the returned right. The function releases every other right
// that the kernel hands out with it.
func taskGetExceptionPort(task machPort, mask uint32) (machPort, error) {
	var masks, ports [excTypesCount]uint32
	var behaviors, flavors [excTypesCount]int32
	count := uint32(excTypesCount)
	r := machCalls.taskGetExceptionPorts.call(uintptr(task), uintptr(mask),
		uintptr(unsafe.Pointer(&masks[0])), uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&ports[0])), uintptr(unsafe.Pointer(&behaviors[0])),
		uintptr(unsafe.Pointer(&flavors[0])))
	runtime.KeepAlive(&masks)
	runtime.KeepAlive(&count)
	runtime.KeepAlive(&ports)
	runtime.KeepAlive(&behaviors)
	runtime.KeepAlive(&flavors)
	if err := kr("task_get_exception_ports", r); err != nil {
		return machPortNull, err
	}
	if count > excTypesCount {
		return machPortNull, fmt.Errorf("task_get_exception_ports returned %d entries, want at most %d", count, excTypesCount)
	}
	hasRight := func(i uint32) bool {
		return ports[i] != uint32(machPortNull) && ports[i] != uint32(machPortDead)
	}
	chosen := -1
	for i := range count {
		if masks[i]&mask != 0 && hasRight(i) {
			chosen = int(i)
			break
		}
	}
	var errs []error
	for i := range count {
		if int(i) == chosen || !hasRight(i) {
			continue
		}
		if err := portDeallocate(selfTask(), machPort(ports[i])); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return machPortNull, fmt.Errorf("release unused exception ports: %w", err)
	}
	if chosen < 0 {
		return machPortNull, nil
	}
	return machPort(ports[chosen]), nil
}

// bootstrapPort returns the task's bootstrap port, or machPortNull on failure.
// The stub rendezvous needs the name server, and the Sentry cannot register a
// service name without it. Each call adds one send-right reference that the
// caller releases with portDeallocate.
func bootstrapPort() machPort {
	var p uint32
	r := machCalls.taskGetSpecialPort.call(uintptr(selfTask()), taskBootstrapPort, uintptr(unsafe.Pointer(&p)))
	runtime.KeepAlive(&p)
	if kernReturn(int32(r)) != kernSuccess {
		return machPortNull
	}
	return machPort(p)
}

// bootstrapRegister publishes the send right of port under name in the
// bootstrap namespace. A translated stub has no inherited port, so it looks
// up this random name to send its first hello. libSystem still exports the
// call although the headers mark it deprecated.
func bootstrapRegister(name string, port machPort) error {
	bp := bootstrapPort()
	if bp == machPortNull {
		return errors.New("bootstrap_register: the task has no bootstrap port")
	}
	cname := append([]byte(name), 0)
	r := machCalls.bootstrapRegister.call(uintptr(bp), uintptr(unsafe.Pointer(&cname[0])), uintptr(port))
	runtime.KeepAlive(cname)
	regErr := kr("bootstrap_register", r)
	var relErr error
	if err := portDeallocate(selfTask(), bp); err != nil {
		relErr = fmt.Errorf("release bootstrap port: %w", err)
	}
	return errors.Join(regErr, relErr)
}

// portModRefsReceive changes the receive-right count of name in task by delta.
// A delta of -1 destroys the rendezvous right after the first hello, so no
// later process can claim the registered name.
func portModRefsReceive(task, name machPort, delta int) error {
	r := machCalls.portModRefs.call(uintptr(task), uintptr(name), machPortRightReceive, uintptr(uint32(int32(delta))))
	return kr("mach_port_mod_refs", r)
}

// machMsgSend sends the message at msg. A zero timeoutMs blocks without limit.
// The hello reply must not hang the Sentry when the stub died, so callers set a timeout.
func machMsgSend(msg unsafe.Pointer, size uint32, timeoutMs uint32) kernReturn {
	option := uint32(machSendMsg)
	if timeoutMs != 0 {
		option |= machSendTimeout
	}
	return machMsgCall(msg, option, size, 0, machPortNull, timeoutMs)
}

func threadSuspend(th machPort) error {
	return kr("thread_suspend", machCalls.threadSuspend.call(uintptr(th)))
}
func threadResume(th machPort) error {
	return kr("thread_resume", machCalls.threadResume.call(uintptr(th)))
}
func threadTerminate(th machPort) error {
	return kr("thread_terminate", machCalls.threadTerminate.call(uintptr(th)))
}
func taskTerminate(task machPort) error {
	return kr("task_terminate", machCalls.taskTerminate.call(uintptr(task)))
}

// ulock operations on a word that two processes share.
const (
	ulCompareAndWaitShared = 3
	ulfWakeAll             = 0x100
)

// ulockWait parks the caller while *addr equals expected. A zero timeout
// blocks without limit. The caller re-reads the word after every return.
func ulockWait(addr *uint32, expected uint32, timeoutMicros uint32) syscall.Errno {
	_, errno := machCalls.ulockWait.call4(ulCompareAndWaitShared, uintptr(unsafe.Pointer(addr)), uintptr(expected), uintptr(timeoutMicros))
	runtime.KeepAlive(addr)
	return errno
}

// ulockWakeAll wakes every thread that waits on addr in any process.
func ulockWakeAll(addr *uint32) {
	machCalls.ulockWake.call4(ulCompareAndWaitShared|ulfWakeAll, uintptr(unsafe.Pointer(addr)), 0, 0)
	runtime.KeepAlive(addr)
}

// vmRemapFrom maps size bytes of srcTask at srcAddr into the Sentry at an
// address that the kernel picks. The mapping shares the pages with the source.
func vmRemapFrom(srcTask machPort, srcAddr, size uint64) (uint64, error) {
	var target uint64
	var cur, max int32
	r := machCalls.vmRemap.call(
		uintptr(selfTask()), uintptr(unsafe.Pointer(&target)), uintptr(size), 0,
		vmFlagsAnywhere, uintptr(srcTask), uintptr(srcAddr), 0,
		uintptr(unsafe.Pointer(&cur)), uintptr(unsafe.Pointer(&max)), vmInheritNone)
	runtime.KeepAlive(&target)
	runtime.KeepAlive(&cur)
	runtime.KeepAlive(&max)
	return target, kr("mach_vm_remap", r)
}
