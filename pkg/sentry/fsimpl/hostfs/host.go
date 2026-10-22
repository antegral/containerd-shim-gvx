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

package hostfs

import (
	"errors"
	"time"
)

// This file defines the contract between the platform-neutral hostfs code and
// the per-platform host access layer. Each platform file set defines a
// hostRoot type with the methods below:
//
//	func newHostRoot(root *os.Root) (*hostRoot, error)
//	func (h *hostRoot) close() error
//	func (h *hostRoot) open(rel string, flags int, perm os.FileMode) (*os.File, error)
//	func (h *hostRoot) openDir(rel string) (*os.File, error)
//	func (h *hostRoot) lstat(rel string) (hostInfo, error)
//	func (h *hostRoot) fstat(f *os.File) (hostInfo, error)
//	func (h *hostRoot) mkdir(rel string) error
//	func (h *hostRoot) unlink(rel string) error
//	func (h *hostRoot) rmdir(rel string) error
//	func (h *hostRoot) rename(oldRel, newRel string) error
//	func (h *hostRoot) link(oldRel, newRel string) error
//	func (h *hostRoot) readlink(rel string) (string, error)
//	func (h *hostRoot) readDir(rel string) ([]hostDirEntry, error)
//	func (h *hostRoot) syncDir(rel string) error
//	func (h *hostRoot) chtimes(rel string, atime, mtime *time.Time) error
//	func (h *hostRoot) caseInsensitive() bool
//	func hostErrno(err error) (error, bool)
//
// Every method takes a cleaned, slash-separated, workspace-relative path with
// no "." or ".." components ("." names the workspace root itself). No method
// may reach a file by absolute path or follow a symbolic link, junction, or
// mount point at any component.

// hostKind is the file type of a host directory entry.
type hostKind uint8

const (
	// hostKindRegular is a regular file.
	hostKindRegular hostKind = iota + 1
	// hostKindDir is a directory.
	hostKindDir
	// hostKindSymlink is a host symbolic link that hostfs may report and read
	// but never traverses.
	hostKindSymlink
	// hostKindOther is any other host object, such as a device, a socket, or a
	// junction. hostfs refuses to open these.
	hostKindOther
)

// hostID identifies a host file independent of the path used to reach it.
// Hard links share one hostID.
type hostID struct {
	dev uint64
	ino uint64
}

// hostInfo is the host metadata of one entry, obtained without following
// symbolic links.
type hostInfo struct {
	kind hostKind
	id   hostID
	size int64
	// blocks is the allocation size in 512-byte units.
	blocks int64
	nlink  uint32
	// perm holds the host permission bits. hostfs uses them only as the
	// default virtual mode of entries that have no .gvx_meta record.
	perm  uint32
	atime time.Time
	mtime time.Time
	ctime time.Time
	btime time.Time
}

// hostDirEntry is one name returned by hostRoot.readDir.
type hostDirEntry struct {
	name string
	kind hostKind
	// ino is the host inode number, or zero when the platform layer does not
	// report it during listing.
	ino uint64
}

// errInvalidHostName reports a name that the host file system cannot store
// without changing its meaning, such as a Windows alternate data stream name.
var errInvalidHostName = errors.New("hostfs: name is not representable on the host file system")

// errNameMismatch reports a name that the host resolves only because it folds
// case or accepts a short alias. It wraps fs.ErrNotExist, because the guest
// asked for a name that does not exist. Callers that create names treat it as
// a collision with the stored name.
var errNameMismatch = errors.New("hostfs: the stored name differs from the requested name")

// errHostUnsupported reports an operation that the host file system cannot
// perform, such as a hard link on a volume without hard link support.
var errHostUnsupported = errors.New("hostfs: operation not supported by the host file system")
