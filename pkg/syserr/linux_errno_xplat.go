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
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux/errno"
)

// linuxErrnoErrors maps a Linux errno to the Error that newWithHost registered
// for it.
var linuxErrnoErrors [maxErrno]*Error

// registerLinuxErrno records e as the Error for a Linux errno. The first
// registration of an errno wins, as it does for host translations.
func registerLinuxErrno(linuxTranslation errno.Errno, e *Error) {
	if int(linuxTranslation) < len(linuxErrnoErrors) && linuxErrnoErrors[linuxTranslation] == nil {
		linuxErrnoErrors[linuxTranslation] = e
	}
}

// fromLinuxErrno converts a Linux errno, as an errors.Error from the linuxerr
// package carries it, to an Error.
//
// WHY: FromHost translates the errno numbers of the host. A Linux host uses the
// Linux numbers, so a lookup through FromHost is the identity there. A Windows
// or macOS host numbers its errors differently. On macOS, Linux EAGAIN (11) is
// EDEADLK and Linux ENOSYS (38) is ENOTSOCK. A lookup through FromHost then
// panics or returns the wrong error.
func fromLinuxErrno(n errno.Errno) *Error {
	if int(n) < len(linuxErrnoErrors) {
		if e := linuxErrnoErrors[n]; e != nil {
			return e
		}
	}
	return NewDynamic(fmt.Sprintf("linux errno %d", n), n)
}
