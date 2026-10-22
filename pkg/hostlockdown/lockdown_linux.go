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

//go:build linux

package hostlockdown

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The Linux lockdown uses Landlock. A Landlock domain denies every new
// path-based file access that no rule allows, including execve, while
// descriptors that the process holds keep working. That matches the macOS
// Seatbelt profile. The domain also inherits to every thread that a locked
// thread creates.
//
// Landlock restricts one thread. The Go runtime runs goroutines on many
// threads, so Apply restricts all of them with syscall.AllThreadsSyscall. The
// Go runtime supports that call only in a build without cgo, so a cgo build
// returns ErrUnsupported.

// Landlock access rights of ABI version 1 to 3.
const (
	landlockFSV1 = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	landlockFSRefer    = unix.LANDLOCK_ACCESS_FS_REFER    // ABI 2
	landlockFSTruncate = unix.LANDLOCK_ACCESS_FS_TRUNCATE // ABI 3

	// landlockNetABI is the first ABI that restricts TCP bind and connect.
	landlockNetABI = 4

	// rulesetSizeV1 and rulesetSizeV4 are the sizes of the ruleset attribute
	// before and after the network fields.
	rulesetSizeV1 = 8
	rulesetSizeV4 = 16
)

// workspaceWriteMask lists the rights that a writable workspace needs on top
// of the read rights.
const workspaceWriteMask = unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
	unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
	unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
	unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
	unix.LANDLOCK_ACCESS_FS_MAKE_REG |
	unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
	unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
	unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
	unix.LANDLOCK_ACCESS_FS_REFER |
	unix.LANDLOCK_ACCESS_FS_TRUNCATE

// workspaceReadMask lists the rights that a read-only workspace keeps.
const workspaceReadMask = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR

// handledFS returns the file access rights that the ruleset handles for the
// Landlock ABI version abi. A handled right is denied unless a rule allows it.
func handledFS(abi int) uint64 {
	mask := uint64(landlockFSV1)
	if abi >= 2 {
		mask |= landlockFSRefer
	}
	if abi >= 3 {
		mask |= landlockFSTruncate
	}
	return mask
}

// landlockABI returns the Landlock ABI version of the kernel.
func landlockABI() (int, error) {
	v, _, errno := syscall.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, errno
	}
	return int(v), nil
}

// allThreads runs one system call on every thread of the process.
func allThreads(trap, a1, a2, a3 uintptr) error {
	if _, _, errno := syscall.AllThreadsSyscall(trap, a1, a2, a3); errno != 0 {
		return errno
	}
	return nil
}

func applyOSLockdown(opts Options) (Status, error) {
	if cgoEnabled {
		return Status{}, fmt.Errorf("%w: the Linux lockdown needs a build with CGO_ENABLED=0", ErrUnsupported)
	}
	abi, err := landlockABI()
	if err != nil {
		return Status{}, fmt.Errorf("%w: Landlock is unavailable (Linux 5.13 or newer with Landlock enabled): %v", ErrUnsupported, err)
	}
	if abi < 1 {
		return Status{}, fmt.Errorf("%w: Landlock ABI %d", ErrUnsupported, abi)
	}

	fs := handledFS(abi)
	attr := unix.LandlockRulesetAttr{Access_fs: fs}
	size := uintptr(rulesetSizeV1)
	blockNet := abi >= landlockNetABI && !opts.AllowOutboundNet
	if abi >= landlockNetABI {
		size = rulesetSizeV4
		if blockNet {
			attr.Access_net = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
		}
	}
	rs, _, errno := syscall.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
	if errno != 0 {
		return Status{}, fmt.Errorf("hostlockdown: landlock_create_ruleset: %w", errno)
	}
	rulesetFD := int(rs)
	defer unix.Close(rulesetFD)

	if opts.WorkspacePath != "" {
		if err := allowWorkspace(rulesetFD, opts, fs); err != nil {
			return Status{}, err
		}
	}

	if err := allThreads(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); err != nil {
		return Status{}, fmt.Errorf("hostlockdown: prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	if err := allThreads(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), 0, 0); err != nil {
		return Status{}, fmt.Errorf("hostlockdown: landlock_restrict_self: %w", err)
	}

	st := Status{}
	if err := probeExecBlocked(); err != nil {
		return st, err
	}
	st.SubprocessBlocked = true
	if err := probeOpenBlocked(opts.WorkspacePath); err != nil {
		return st, err
	}
	st.UnboundFileOpenBlocked = true
	if blockNet {
		if err := probeConnectBlocked(); err != nil {
			return st, err
		}
		st.NetworkOutboundBlocked = true
	}
	return st, nil
}

// allowWorkspace adds the rule that lets the process use the workspace tree.
func allowWorkspace(rulesetFD int, opts Options, handled uint64) error {
	fd, err := unix.Open(opts.WorkspacePath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("hostlockdown: open workspace %q: %w", opts.WorkspacePath, err)
	}
	defer unix.Close(fd)
	allowed := uint64(workspaceReadMask)
	if !opts.WorkspaceReadOnly {
		allowed |= workspaceWriteMask
	}
	// A rule may name only rights that the ruleset handles.
	rule := unix.LandlockPathBeneathAttr{Allowed_access: allowed & handled, Parent_fd: int32(fd)}
	if _, _, errno := syscall.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFD), unix.LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("hostlockdown: landlock_add_rule for %q: %w", opts.WorkspacePath, errno)
	}
	return nil
}

// probeExecBlocked proves that the process cannot start a program. The probe
// forks and executes an existing file in the child. The lockdown makes the exec
// fail with EACCES, and ForkExec reports that error. A missing lockdown starts
// the program, and the probe reaps it and fails.
func probeExecBlocked() error {
	for _, path := range []string{"/bin/true", "/usr/bin/true", "/bin/sh", "/usr/bin/env"} {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		pid, err := syscall.ForkExec(path, []string{path}, &syscall.ProcAttr{})
		if err == nil {
			var ws syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &ws, 0, nil)
			return fmt.Errorf("hostlockdown: the exec probe started %s", path)
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return nil
		}
		return fmt.Errorf("hostlockdown: exec probe of %s returned %v, want EACCES", path, err)
	}
	return errors.New("hostlockdown: no executable file exists for the exec probe")
}

// probeOpenBlocked proves that a new open outside the workspace fails.
func probeOpenBlocked(workspace string) error {
	for _, path := range []string{"/etc/passwd", "/etc/hostname", "/proc/self/status"} {
		if workspace != "" && pathBeneath(path, workspace) {
			continue
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			unix.Close(fd)
			return fmt.Errorf("hostlockdown: open probe of %s succeeded", path)
		}
		if errors.Is(err, unix.EACCES) {
			return nil
		}
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		return fmt.Errorf("hostlockdown: open probe of %s returned %v, want EACCES", path, err)
	}
	return errors.New("hostlockdown: no readable file exists for the open probe")
}

func pathBeneath(path, dir string) bool {
	if len(path) < len(dir) || path[:len(dir)] != dir {
		return false
	}
	return len(path) == len(dir) || path[len(dir)] == '/' || dir[len(dir)-1] == '/'
}

// probeConnectBlocked proves that a new outbound TCP connection fails. The
// connection targets a closed loopback port, so a missing restriction returns
// ECONNREFUSED and a working one returns EACCES.
func probeConnectBlocked() error {
	c, err := net.Dial("tcp", "127.0.0.1:1")
	if err == nil {
		_ = c.Close()
		return errors.New("hostlockdown: TCP connect probe succeeded")
	}
	if errors.Is(err, unix.EACCES) {
		return nil
	}
	return fmt.Errorf("hostlockdown: TCP connect probe returned %v, want EACCES", err)
}
