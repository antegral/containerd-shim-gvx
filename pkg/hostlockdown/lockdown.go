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

// Package hostlockdown applies irreversible host OS self-containment to the
// current process after all required host handles are open. Windows uses a
// restricted token, Low integrity, a job object and no win32k. macOS uses a
// Seatbelt profile and RLIMIT_NPROC=0.
package hostlockdown

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
)

// ErrUnsupported reports that the host OS has no lockdown implementation.
// Apply never returns a success Status when it enforces nothing.
var ErrUnsupported = errors.New("hostlockdown: unsupported host OS")

// ErrNotLockedDown reports that BindThread ran before a successful Apply.
var ErrNotLockedDown = errors.New("hostlockdown: Apply has not succeeded")

// Options configures the host OS lockdown boundary.
type Options struct {
	// WorkspacePath is the optional host workspace directory. The locked
	// process may open files below it. It must exist when Apply runs.
	WorkspacePath string

	// WorkspaceReadOnly limits the locked process to read access below
	// WorkspacePath.
	WorkspaceReadOnly bool

	// AllowOutboundNet permits new outbound TCP and UDP connections and accept
	// on pre-bound listeners when Track A (-net=nat) is active. Apply
	// blocks all outbound traffic when AllowOutboundNet is false and
	// OutboundUDPPorts is empty.
	AllowOutboundNet bool

	// OutboundUDPPorts lists remote UDP ports that pre-bound UDP sockets may
	// send to and receive from. The -net=wg backend sets the WireGuard peer
	// port here. Seatbelt can match remote ports but not remote addresses.
	// Ignored when AllowOutboundNet is true.
	OutboundUDPPorts []uint16

	// ReadPaths lists extra host files and directories that the locked process
	// may read. Only Linux supports it, because only Landlock restricts reads
	// by path. Apply returns an error on another host when the list is not
	// empty.
	ReadPaths []string
}

// Status reports the containment primitives enforced by Apply. Apply sets a
// field only after the OS call succeeded. It also observes the effect with a
// self-probe in the locked process or by reading the OS state back.
type Status struct {
	Applied bool

	// SubprocessBlocked reports that the kernel rejects new child processes.
	// macOS: a spawn probe failed. Windows: the process belongs to a job
	// with an active process limit of one.
	SubprocessBlocked bool

	// UnboundFileOpenBlocked reports that opens outside the workspace fail.
	// macOS: probe opens failed in the whole process. Windows: probe opens
	// failed on a thread that holds the restricted token, so only threads
	// that call BindThread have this property.
	UnboundFileOpenBlocked bool

	// IntegrityDowngraded reports a Low integrity primary token. Windows only.
	IntegrityDowngraded bool

	// Win32kBlocked reports that win32k system calls are disabled. Windows only.
	Win32kBlocked bool

	// NetworkOutboundBlocked reports that a self-probe observed a rejected
	// outbound TCP connect. Apply leaves it false when the options allow
	// outbound traffic.
	NetworkOutboundBlocked bool

	SeatbeltProfile string
}

var (
	lockdownMu     sync.Mutex
	lockedDownFlag atomic.Bool
	lastStatus     Status
)

// Apply locks down the current host process using OS-native containment
// primitives. Apply is idempotent within a process.
//
// Apply returns an error when any required primitive fails to install or when
// a self-probe shows that the primitive does not hold. After an error the
// process can be partly locked and the caller must stop using it.
//
// Precondition: Open all hypervisor handles, cached .erofs layer descriptors,
// network listeners/sockets, and the /workspace os.Root handle before calling
// Apply.
func Apply(opts Options) (Status, error) {
	lockdownMu.Lock()
	defer lockdownMu.Unlock()
	if lockedDownFlag.Load() {
		return lastStatus, nil
	}
	for _, port := range opts.OutboundUDPPorts {
		if port == 0 {
			return Status{}, errors.New("hostlockdown: OutboundUDPPorts contains port 0")
		}
	}
	if len(opts.ReadPaths) > 0 && runtime.GOOS != "linux" {
		return Status{}, fmt.Errorf("hostlockdown: ReadPaths needs Linux, not %s", runtime.GOOS)
	}
	st, err := applyOSLockdown(opts)
	if err != nil {
		return st, err
	}
	st.Applied = true
	lastStatus = st
	lockedDownFlag.Store(true)
	return st, nil
}

// IsLockedDown reports whether Apply has succeeded in the current process.
func IsLockedDown() bool {
	return lockedDownFlag.Load()
}
