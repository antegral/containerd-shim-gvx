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

//go:build darwin

package hostlockdown

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

//go:linkname darwinSyscall6 syscall.syscall6
func darwinSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

func sandboxInitWithParametersTrampoline()
func addrOfSandboxInitWithParameters() uintptr
func sandboxFreeErrorTrampoline()
func addrOfSandboxFreeError() uintptr

// Seatbelt parameter names. The profile refers to them with (param "NAME") so
// that path strings never appear inside the SBPL text.
const (
	paramWorkspace     = "WORKSPACE_DIR"
	paramWorkspaceReal = "WORKSPACE_DIR_REAL"
)

// BuildSeatbeltProfile returns the macOS Seatbelt SBPL policy for opts.
//
// The policy starts from (deny default). On macOS 26 the locked process needs
// no allow rule for the Go runtime, thread creation, timers or signals to
// itself. Hypervisor.framework calls on the existing VM need none either.
// Seatbelt authorizes files at open time, so descriptors opened before Apply
// stay usable. The rules below add only the paths and sockets that a
// configuration names.
//
// SBPL applies the last matching rule, so the explicit process denies come
// last. They keep fork and exec blocked even if a future allow rule matches.
func BuildSeatbeltProfile(opts Options) string {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")
	// Helpers that started before Apply, such as the systrap stub, stay
	// signalable for shutdown. Apply blocks fork, so no other child can exist.
	b.WriteString("(allow signal (target children))\n")
	if opts.WorkspacePath != "" {
		// Seatbelt evaluates the resolved path of every open, including
		// openat relative to a pinned directory descriptor.
		ops := "file-read* file-write*"
		if opts.WorkspaceReadOnly {
			ops = "file-read*"
		}
		fmt.Fprintf(&b, "(allow %s (subpath (param %q)))\n", ops, paramWorkspace)
		fmt.Fprintf(&b, "(allow %s (subpath (param %q)))\n", ops, paramWorkspaceReal)
	}
	switch {
	case opts.AllowOutboundNet:
		b.WriteString("(allow network-outbound)\n")
		b.WriteString("(allow network-inbound)\n")
		b.WriteString(denyNewBind)
	case len(opts.OutboundUDPPorts) > 0:
		for _, port := range opts.OutboundUDPPorts {
			fmt.Fprintf(&b, "(allow network-outbound (remote udp \"*:%d\"))\n", port)
		}
		b.WriteString("(allow network-inbound (local udp \"*:*\"))\n")
		b.WriteString(denyNewBind)
	}
	b.WriteString("(deny process-fork)\n")
	b.WriteString("(deny process-exec*)\n")
	return b.String()
}

// denyNewBind follows every network-inbound allow. network-inbound also
// grants bind, and only pre-bound sockets may receive traffic.
const denyNewBind = "(deny network-bind)\n"

func applyOSLockdown(opts Options) (Status, error) {
	var params []string
	var workspaceReal string
	if opts.WorkspacePath != "" {
		absWS, err := filepath.Abs(opts.WorkspacePath)
		if err != nil {
			return Status{}, fmt.Errorf("hostlockdown: resolve workspace %q: %w", opts.WorkspacePath, err)
		}
		workspaceReal, err = filepath.EvalSymlinks(absWS)
		if err != nil {
			return Status{}, fmt.Errorf("hostlockdown: resolve workspace symlinks %q: %w", absWS, err)
		}
		if workspaceReal == "/" {
			return Status{}, errors.New("hostlockdown: workspace \"/\" would allow every host file")
		}
		params = append(params, paramWorkspace, absWS, paramWorkspaceReal, workspaceReal)
	}
	profile := BuildSeatbeltProfile(opts)

	desc, err := newDescriptorProbe()
	if err != nil {
		return Status{}, err
	}
	defer desc.close()

	// 1. Set RLIMIT_NPROC = 0 to block fork() at the XNU kernel boundary.
	if err := unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return Status{}, fmt.Errorf("hostlockdown: setrlimit RLIMIT_NPROC: %w", err)
	}

	// 2. Compile and apply the Seatbelt SBPL profile via sandbox_init_with_parameters.
	if err := sandboxInit(profile, params); err != nil {
		return Status{}, err
	}

	// 3. Verify in the locked process that the kernel enforces each property.
	if err := probeSubprocessBlocked(); err != nil {
		return Status{}, err
	}
	if err := probeUnlistedOpenBlocked(workspaceReal); err != nil {
		return Status{}, err
	}
	if workspaceReal != "" {
		if err := probeWorkspaceReachable(workspaceReal); err != nil {
			return Status{}, err
		}
	}
	if err := desc.verify(); err != nil {
		return Status{}, err
	}
	st := Status{
		SubprocessBlocked:      true,
		UnboundFileOpenBlocked: true,
		SeatbeltProfile:        profile,
	}
	if !opts.AllowOutboundNet {
		if err := probeOutboundBlocked(); err != nil {
			return Status{}, err
		}
		st.NetworkOutboundBlocked = true
	}
	return st, nil
}

var (
	sandboxInitMu sync.Mutex
	sandboxErrBuf *byte
)

// sandboxInit compiles profile and applies it to the calling process. The
// kv slice holds alternating Seatbelt parameter names and values.
func sandboxInit(profile string, kv []string) error {
	profileBytes, err := unix.ByteSliceFromString(profile)
	if err != nil {
		return fmt.Errorf("hostlockdown: encode Seatbelt profile: %w", err)
	}
	var params []*byte
	for _, s := range kv {
		p, err := unix.BytePtrFromString(s)
		if err != nil {
			return fmt.Errorf("hostlockdown: encode Seatbelt parameter: %w", err)
		}
		params = append(params, p)
	}
	var paramsPtr uintptr
	if len(params) > 0 {
		params = append(params, nil)
		paramsPtr = uintptr(unsafe.Pointer(&params[0]))
	}

	// The libc call writes the error text pointer through errBuf. A
	// package variable never moves, unlike a stack slot that the runtime may
	// relocate while only a uintptr names it.
	sandboxInitMu.Lock()
	defer sandboxInitMu.Unlock()
	sandboxErrBuf = nil
	r1, _, errno := darwinSyscall6(
		addrOfSandboxInitWithParameters(),
		uintptr(unsafe.Pointer(&profileBytes[0])),
		0,
		paramsPtr,
		uintptr(unsafe.Pointer(&sandboxErrBuf)),
		0,
		0,
	)
	runtime.KeepAlive(profileBytes)
	runtime.KeepAlive(params)
	if int32(r1) == 0 {
		return nil
	}
	detail := "no error text"
	if errBuf := sandboxErrBuf; errBuf != nil {
		detail = unix.BytePtrToString(errBuf)
		darwinSyscall6(addrOfSandboxFreeError(), uintptr(unsafe.Pointer(errBuf)), 0, 0, 0, 0, 0)
		sandboxErrBuf = nil
	}
	return fmt.Errorf("hostlockdown: sandbox_init_with_parameters rc=%d errno=%v: %s", int32(r1), errno, detail)
}

//go:cgo_import_dynamic libc_sandbox_init_with_parameters sandbox_init_with_parameters "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_sandbox_free_error sandbox_free_error "/usr/lib/libSystem.B.dylib"
