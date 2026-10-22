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

//go:build windows

package hostfs

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// ntError reports a failed native call. It unwraps to the NTSTATUS value and
// to the Win32 error that NTSTATUS value converts to. The Win32 error lets
// errors.Is match fs.ErrNotExist, fs.ErrExist, and fs.ErrPermission, because
// NTSTATUS has no such methods. The NTSTATUS value keeps the detail that the
// Win32 conversion loses, such as STATUS_FILE_IS_A_DIRECTORY.
type ntError struct {
	op     string
	path   string
	dest   string
	status windows.NTStatus
}

func (e *ntError) Error() string {
	if e.dest != "" {
		return fmt.Sprintf("hostfs: %s %q to %q: %s", e.op, e.path, e.dest, e.status.Error())
	}
	return fmt.Sprintf("hostfs: %s %q: %s", e.op, e.path, e.status.Error())
}

func (e *ntError) Unwrap() []error {
	return []error{e.status, e.status.Errno()}
}

// hostError adds the operation and the path to err. A native status becomes
// an ntError. ErrPathTraversal passes through unchanged so that callers can
// compare it directly. Every other error keeps its chain through %w.
func hostError(op, rel string, err error) error {
	if status, ok := err.(windows.NTStatus); ok {
		return &ntError{op: op, path: rel, status: status}
	}
	if err == ErrPathTraversal {
		return err
	}
	return fmt.Errorf("hostfs: %s %q: %w", op, rel, err)
}

// hostError2 is hostError for an operation on two paths.
func hostError2(op, from, to string, err error) error {
	if status, ok := err.(windows.NTStatus); ok {
		return &ntError{op: op, path: from, dest: to, status: status}
	}
	if err == ErrPathTraversal {
		return err
	}
	return fmt.Errorf("hostfs: %s %q to %q: %w", op, from, to, err)
}

// hostErrno maps a Windows error found inside err to the Linux errno that
// guest code expects. Native statuses map directly where the Win32 conversion
// would lose the meaning, and through their Win32 equivalent otherwise.
// Errors that have no Linux equivalent return false.
func hostErrno(err error) (error, bool) {
	if err == nil {
		return nil, false
	}
	switch {
	case errors.Is(err, errInvalidHostName):
		return linuxerr.EINVAL, true
	case errors.Is(err, errHostUnsupported):
		return linuxerr.EOPNOTSUPP, true
	case errors.Is(err, fs.ErrInvalid):
		return linuxerr.EINVAL, true
	}
	var status windows.NTStatus
	if errors.As(err, &status) {
		if mapped, ok := ntStatusErrno(status); ok {
			return mapped, true
		}
		return win32Errno(status.Errno())
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return win32Errno(errno)
	}
	return nil, false
}

// ntStatusErrno maps the native statuses whose meaning the Win32 conversion
// loses or blurs. Only STATUS_NOT_SUPPORTED and STATUS_INVALID_DEVICE_REQUEST
// become EOPNOTSUPP, because other failures of the information classes do not
// prove that the file system lacks the feature.
func ntStatusErrno(status windows.NTStatus) (error, bool) {
	switch status {
	case windows.STATUS_OBJECT_NAME_NOT_FOUND,
		windows.STATUS_OBJECT_PATH_NOT_FOUND,
		windows.STATUS_NO_SUCH_FILE,
		windows.STATUS_OBJECT_NAME_INVALID,
		windows.STATUS_OBJECT_PATH_INVALID,
		windows.STATUS_OBJECT_PATH_SYNTAX_BAD:
		return linuxerr.ENOENT, true
	case windows.STATUS_NOT_A_DIRECTORY:
		return linuxerr.ENOTDIR, true
	case windows.STATUS_FILE_IS_A_DIRECTORY:
		return linuxerr.EISDIR, true
	case windows.STATUS_OBJECT_NAME_COLLISION:
		return linuxerr.EEXIST, true
	case windows.STATUS_DIRECTORY_NOT_EMPTY:
		return linuxerr.ENOTEMPTY, true
	case windows.STATUS_NOT_SUPPORTED, windows.STATUS_INVALID_DEVICE_REQUEST:
		return linuxerr.EOPNOTSUPP, true
	}
	return nil, false
}

// win32Errno maps a Win32 error code to a Linux errno.
func win32Errno(errno syscall.Errno) (error, bool) {
	switch errno {
	case windows.ERROR_FILE_NOT_FOUND,
		windows.ERROR_PATH_NOT_FOUND,
		windows.ERROR_INVALID_NAME,
		windows.ERROR_BAD_PATHNAME:
		return linuxerr.ENOENT, true
	case windows.ERROR_ACCESS_DENIED:
		return linuxerr.EACCES, true
	case windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION:
		return linuxerr.EBUSY, true
	case windows.ERROR_DIR_NOT_EMPTY:
		return linuxerr.ENOTEMPTY, true
	case windows.ERROR_DIRECTORY:
		return linuxerr.ENOTDIR, true
	case windows.ERROR_ALREADY_EXISTS, windows.ERROR_FILE_EXISTS:
		return linuxerr.EEXIST, true
	case windows.ERROR_NOT_SAME_DEVICE:
		return linuxerr.EXDEV, true
	case windows.ERROR_DISK_FULL, windows.ERROR_HANDLE_DISK_FULL:
		return linuxerr.ENOSPC, true
	case windows.ERROR_TOO_MANY_LINKS:
		return linuxerr.EMLINK, true
	case windows.ERROR_NOT_SUPPORTED:
		return linuxerr.EOPNOTSUPP, true
	case windows.ERROR_FILENAME_EXCED_RANGE, windows.ERROR_BUFFER_OVERFLOW:
		return linuxerr.ENAMETOOLONG, true
	case windows.ERROR_WRITE_PROTECT:
		return linuxerr.EROFS, true
	case windows.ERROR_PRIVILEGE_NOT_HELD:
		return linuxerr.EPERM, true
	case windows.ERROR_NOT_A_REPARSE_POINT, windows.ERROR_REPARSE_TAG_MISMATCH:
		return linuxerr.EINVAL, true
	}
	return nil, false
}
