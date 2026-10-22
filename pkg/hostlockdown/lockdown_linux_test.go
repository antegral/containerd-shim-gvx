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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// childEnv marks the process that applies the lockdown. The lockdown is
// irreversible, so each case runs in its own child of the test binary.
const childEnv = "GVX_HOSTLOCKDOWN_CHILD"

// runChild runs the named test in a child process and returns its output.
func runChild(t *testing.T, name string, env ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), append([]string{childEnv + "=1"}, env...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// skipUnlessLockable skips a child in a cgo build, because the lockdown needs
// CGO_ENABLED=0 and the CI runs these tests in that build. In another build, it
// fails a child that runs where the lockdown cannot apply, unless
// GVX_ALLOW_NO_LANDLOCK=1 names the host as a kernel older than Landlock ABI 8.
func skipUnlessLockable(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrUnsupported) {
		return
	}
	if cgoEnabled {
		t.Skipf("the Linux lockdown needs CGO_ENABLED=0: %v", err)
	}
	if os.Getenv("GVX_ALLOW_NO_LANDLOCK") == "1" {
		t.Skipf("the host cannot apply the Linux lockdown: %v", err)
	}
	t.Fatalf("the host cannot apply the Linux lockdown: %v (set GVX_ALLOW_NO_LANDLOCK=1 to skip on a known host)", err)
}

func TestLinuxLockdownBlocksExecAndUnboundOpens(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		out, err := runChild(t, "TestLinuxLockdownBlocksExecAndUnboundOpens", "GVX_WORKSPACE="+t.TempDir())
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		if strings.Contains(out, "--- SKIP") {
			t.Skip(out)
		}
		return
	}
	workspace := os.Getenv("GVX_WORKSPACE")
	if err := os.WriteFile(filepath.Join(workspace, "inside.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	preopened, err := os.Open("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	defer preopened.Close()

	st, err := Apply(Options{WorkspacePath: workspace})
	skipUnlessLockable(t, err)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !st.Applied || !st.SubprocessBlocked || !st.UnboundFileOpenBlocked {
		t.Fatalf("Status = %+v, want applied with the subprocess and open blocks", st)
	}

	// A descriptor that the process held before the lockdown keeps working.
	buf := make([]byte, 4)
	if _, err := preopened.Read(buf); err != nil {
		t.Errorf("read of a pre-opened descriptor: %v", err)
	}
	// The workspace stays usable, and nothing else opens.
	if data, err := os.ReadFile(filepath.Join(workspace, "inside.txt")); err != nil || string(data) != "inside" {
		t.Errorf("read inside the workspace = %q, %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "new.txt"), []byte("x"), 0o600); err != nil {
		t.Errorf("write inside the workspace: %v", err)
	}
	if _, err := os.Open("/etc/hostname"); !errors.Is(err, unix.EACCES) {
		t.Errorf("open outside the workspace: %v, want EACCES", err)
	}
	if err := exec.Command("/bin/true").Run(); err == nil {
		t.Error("exec of /bin/true succeeded")
	}
}

func TestLinuxLockdownReadOnlyWorkspace(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		out, err := runChild(t, "TestLinuxLockdownReadOnlyWorkspace", "GVX_WORKSPACE="+t.TempDir())
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		if strings.Contains(out, "--- SKIP") {
			t.Skip(out)
		}
		return
	}
	workspace := os.Getenv("GVX_WORKSPACE")
	if err := os.WriteFile(filepath.Join(workspace, "ro.txt"), []byte("ro"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Apply(Options{WorkspacePath: workspace, WorkspaceReadOnly: true})
	skipUnlessLockable(t, err)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(workspace, "ro.txt")); err != nil || string(data) != "ro" {
		t.Errorf("read of a read-only workspace = %q, %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "ro.txt"), []byte("x"), 0o600); !errors.Is(err, unix.EACCES) {
		t.Errorf("write to a read-only workspace: %v, want EACCES", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "new.txt"), []byte("x"), 0o600); !errors.Is(err, unix.EACCES) {
		t.Errorf("create in a read-only workspace: %v, want EACCES", err)
	}
}

func TestLinuxApplyRefusesWithoutLandlockOrWithCgo(t *testing.T) {
	// The check order is part of the contract: a build that cannot restrict all
	// threads reports ErrUnsupported before it changes any process state.
	if !cgoEnabled {
		t.Skip("the build has no cgo, so the refusal does not apply")
	}
	if _, err := applyOSLockdown(Options{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("applyOSLockdown with cgo = %v, want ErrUnsupported", err)
	}
}

func TestPathBeneath(t *testing.T) {
	for _, c := range []struct {
		path, dir string
		want      bool
	}{
		{"/work/a", "/work", true},
		{"/work", "/work", true},
		{"/workspace/a", "/work", false},
		{"/etc/passwd", "/work", false},
		{"/work/a", "/work/", true},
	} {
		if got := pathBeneath(c.path, c.dir); got != c.want {
			t.Errorf("pathBeneath(%q, %q) = %v, want %v", c.path, c.dir, got, c.want)
		}
	}
}
