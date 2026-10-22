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
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// libcSyscall6 calls a C function with six word arguments on the system stack.
// The uintptrescapes directive keeps every object whose address a caller passes
// as a uintptr on the heap and alive, because a stack growth would otherwise
// move it under the call.
//
//go:linkname libcSyscall6 syscall.syscall6
//go:uintptrescapes
func libcSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

func libcCallTramp()
func addrOfLibcCall() uintptr
func dlsymTramp()
func addrOfDlsym() uintptr
func taskSelfTrampoline()
func addrOfTaskSelf() uintptr

//go:cgo_import_dynamic libc_dlsym dlsym "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_task_self_trap task_self_trap "/usr/lib/libSystem.B.dylib"

// rtldDefault is RTLD_DEFAULT on Darwin: dlsym searches every loaded image.
const rtldDefault = ^uintptr(1)

// libcFunc is the address of a libSystem function.
type libcFunc uintptr

// libcArgs holds up to twelve argument words for libcCallTramp.
type libcArgs [12]uintptr

var libcCallAddr = addrOfLibcCall()

// resolveLibc looks up a libSystem symbol with dlsym.
func resolveLibc(name string) (libcFunc, error) {
	b := append([]byte(name), 0)
	r, _, _ := libcSyscall6(addrOfDlsym(), rtldDefault, uintptr(unsafe.Pointer(&b[0])), 0, 0, 0, 0)
	runtime.KeepAlive(b)
	if r == 0 {
		return 0, fmt.Errorf("libSystem symbol %q not found", name)
	}
	return libcFunc(r), nil
}

// mustResolve resolves a symbol and panics if libSystem lacks it.
// Every symbol is a documented or long-standing libSystem export, so a miss
// means the host OS is unsupported and the package cannot work at all.
func mustResolve(name string) libcFunc {
	f, err := resolveLibc(name)
	if err != nil {
		panic(err)
	}
	return f
}

// call invokes fn with up to twelve word arguments and returns its result.
//
//go:uintptrescapes
func (fn libcFunc) call(args ...uintptr) uintptr {
	var a libcArgs
	copy(a[:], args)
	r, _, _ := libcSyscall6(libcCallAddr, uintptr(fn), uintptr(unsafe.Pointer(&a)), 0, 0, 0, 0)
	runtime.KeepAlive(&a)
	return r
}

// call4 invokes fn through the runtime's native C-call path with four words.
// It avoids the argument array on the hot ulock paths.
//
//go:uintptrescapes
func (fn libcFunc) call4(a1, a2, a3, a4 uintptr) (uintptr, syscall.Errno) {
	r, _, errno := libcSyscall6(uintptr(fn), a1, a2, a3, a4, 0, 0)
	return r, errno
}

// selfTask returns the Sentry's own task port.
func selfTask() machPort {
	r, _, _ := libcSyscall6(addrOfTaskSelf(), 0, 0, 0, 0, 0, 0)
	return machPort(uint32(r))
}

// addrPtr converts the address of memory that the Go runtime does not manage,
// such as a Mach VM allocation, into a pointer.
func addrPtr(addr uint64) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&addr))
}
