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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

func TestWindowsPinnedCallsVerifyTheStoredCase(t *testing.T) {
	h, _ := winTestHost(t)
	if err := h.mkdir("Dir"); err != nil {
		t.Fatalf("mkdir(Dir) = %v", err)
	}
	winTestWrite(t, h, "Dir/Case.txt", "x")
	if !h.caseVerified() {
		t.Fatal("caseVerified() = false, want true: lstatAt and openDirAt compare the stored name")
	}
	root := h.rootDir()

	for _, name := range []string{"dir", "DIR"} {
		if _, err := h.lstatAt(root, name); !errors.Is(err, errNameMismatch) || !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("lstatAt(%q) = %v, want a case mismatch that wraps not-exist", name, err)
		}
		if _, _, err := h.openDirAt(root, name); !errors.Is(err, errNameMismatch) || !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("openDirAt(%q) = %v, want a case mismatch that wraps not-exist", name, err)
		}
	}
	dir, info, err := h.openDirAt(root, "Dir")
	if err != nil {
		t.Fatalf("openDirAt(Dir) = %v", err)
	}
	defer func() {
		if err := h.closeDir(dir); err != nil {
			t.Errorf("closeDir() = %v", err)
		}
	}()
	if info.kind != hostKindDir {
		t.Errorf("openDirAt(Dir) kind = %v, want a directory", info.kind)
	}
	if _, err := h.lstatAt(dir, "case.txt"); !errors.Is(err, errNameMismatch) {
		t.Errorf("lstatAt(case.txt) = %v, want a case mismatch", err)
	}
	if got, err := h.lstatAt(dir, "Case.txt"); err != nil || got.kind != hostKindRegular || got.size != 1 {
		t.Errorf("lstatAt(Case.txt) = (%+v, %v), want a regular file of size 1", got, err)
	}
	if got, err := h.fstatDir(dir); err != nil || got.id != info.id {
		t.Errorf("fstatDir() = (%+v, %v), want the identity of openDirAt", got, err)
	}
}

func TestWindowsPinnedOpenResolvesInsideTheDirectoryOnly(t *testing.T) {
	h, _ := winTestHost(t)
	if err := h.mkdir("d"); err != nil {
		t.Fatalf("mkdir(d) = %v", err)
	}
	winTestWrite(t, h, "d/f", "payload")
	root := h.rootDir()
	dir, _, err := h.openDirAt(root, "d")
	if err != nil {
		t.Fatalf("openDirAt(d) = %v", err)
	}
	defer func() { _ = h.closeDir(dir) }()

	f, err := h.openChildAt(dir, "f", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("openChildAt(f) = %v", err)
	}
	data, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || string(data) != "payload" {
		t.Fatalf("read through openChildAt = (%q, %v), want payload", data, err)
	}
	for _, name := range []string{"", ".", "..", `..\d`, "d/f", `d\f`, "f:stream"} {
		if f, err := h.openChildAt(dir, name, os.O_RDONLY, 0); err == nil {
			_ = f.Close()
			t.Errorf("openChildAt(%q) succeeded, want a refusal", name)
		}
		if _, err := h.lstatAt(dir, name); err == nil {
			t.Errorf("lstatAt(%q) succeeded, want a refusal", name)
		}
		if _, _, err := h.openDirAt(dir, name); err == nil {
			t.Errorf("openDirAt(%q) succeeded, want a refusal", name)
		}
	}
	_, err = h.lstatAt(dir, "missing")
	winTestErrno(t, err, linuxerr.ENOENT)
}

func TestWindowsPinnedOpenRefusesReparsePoints(t *testing.T) {
	h, dir := winTestHost(t)
	if err := h.mkdir("real"); err != nil {
		t.Fatalf("mkdir(real) = %v", err)
	}
	winTestWrite(t, h, "real/f", "x")
	winTestSymlink(t, "real", filepath.Join(dir, "linkdir"))
	winTestJunction(t, filepath.Join(dir, "junction"), filepath.Join(dir, "real"))
	root := h.rootDir()

	for _, name := range []string{"linkdir", "junction"} {
		if _, _, err := h.openDirAt(root, name); !errors.Is(err, ErrPathTraversal) {
			t.Errorf("openDirAt(%q) = %v, want ErrPathTraversal", name, err)
		}
		if f, err := h.openChildAt(root, name, os.O_RDONLY, 0); err == nil {
			_ = f.Close()
			t.Errorf("openChildAt(%q) succeeded, want a refusal", name)
		}
	}
}

func TestWindowsWorkspaceRenamesAndRemovesDirectoriesWithPinnedHandles(t *testing.T) {
	e, _, _ := newCountEnv(t)
	e.mustMkdir("a")
	e.mustMkdir("a/b")
	e.writeFile("a/b/f", []byte("payload"))
	e.mustStat("a/b/f")
	if e.ws.pinCount() == 0 {
		t.Fatal("no pinned handle after lookups")
	}

	// NTFS refuses to rename a directory that has an open handle below it.
	// The workspace closes its own handles first, so the rename must work.
	if err := e.rename("a", "z"); err != nil {
		t.Fatalf("rename of a directory with pinned handles: %v", err)
	}
	if got := e.readFile("z/b/f"); string(got) != "payload" {
		t.Fatalf("read after the rename = %q, want payload", got)
	}
	// The path API shares the same handles and must close them too.
	if err := e.ws.Rename("z", "y"); err != nil {
		t.Fatalf("Workspace.Rename of a directory with pinned handles: %v", err)
	}
	if err := e.unlink("y/b/f"); err != nil {
		t.Fatal(err)
	}
	e.mustStat("y/b")
	for _, d := range []string{"y/b", "y"} {
		if _, err := e.stat(d + "/none"); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Fatalf("stat %s/none = %v, want ENOENT", d, err)
		}
		if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop(d)); err != nil {
			t.Fatalf("rmdir %s with a pinned handle: %v", d, err)
		}
	}
}
