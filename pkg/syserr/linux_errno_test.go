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

package syserr

import (
	"testing"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux/errno"
	"z.gfire.dev/gvx/pkg/errors"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// linuxErrorFor returns the linuxerr error for a Linux errno, or nil when the
// linuxerr package defines none.
func linuxErrorFor(n int) (e *errors.Error) {
	defer func() {
		if recover() != nil {
			e = nil
		}
	}()
	err := linuxerr.ErrorFromUnix(unix.Errno(n))
	if err == nil {
		return nil
	}
	return err.(*errors.Error)
}

// TestFromErrorKeepsTheLinuxErrno checks that a linuxerr error keeps its Linux
// number on every host. The number is the one that the guest sees, so it must
// not pass through the errno table of the host.
func TestFromErrorKeepsTheLinuxErrno(t *testing.T) {
	checked := 0
	for n := 1; n < 134; n++ {
		e := linuxErrorFor(n)
		if e == nil {
			continue
		}
		checked++
		got := FromError(e).ToLinux()
		if got != errno.Errno(n) {
			t.Errorf("FromError(%v).ToLinux() = %d, want %d", e, got, n)
		}
	}
	if checked < 100 {
		t.Fatalf("checked only %d linuxerr errors", checked)
	}
}

// TestFromErrorNamesTheCommonErrors pins the errors that differ most between
// Linux and macOS numbering. FromHost on macOS panics for the first and returns
// ENOTSOCK for the second.
func TestFromErrorNamesTheCommonErrors(t *testing.T) {
	for _, c := range []struct {
		name string
		err  *errors.Error
		want errno.Errno
	}{
		{"EAGAIN", linuxerr.EAGAIN, errno.EAGAIN},
		{"ENOSYS", linuxerr.ENOSYS, errno.ENOSYS},
		{"ECONNREFUSED", linuxerr.ECONNREFUSED, errno.ECONNREFUSED},
		{"EADDRINUSE", linuxerr.EADDRINUSE, errno.EADDRINUSE},
		{"ETIMEDOUT", linuxerr.ETIMEDOUT, errno.ETIMEDOUT},
	} {
		if got := FromError(c.err).ToLinux(); got != c.want {
			t.Errorf("%s: ToLinux() = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestFromErrorKeepsAnErrnoThatHasNoHostName(t *testing.T) {
	// No syserr value owns errno 133 (EHWPOISON) on every host, so the lookup
	// falls back to a dynamic error that still carries the number.
	got := fromLinuxErrno(errno.Errno(maxErrno - 1))
	if got.ToLinux() != errno.Errno(maxErrno-1) {
		t.Fatalf("fromLinuxErrno(%d).ToLinux() = %d", maxErrno-1, got.ToLinux())
	}
}
