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

//go:build darwin && arm64

package systrap

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEmbeddedStubMatchesSources rebuilds the stub from its sources and
// compares the bytes with the embedded image. The build is deterministic, so a
// difference means that the sources and the committed image drifted apart.
func TestEmbeddedStubMatchesSources(t *testing.T) {
	for _, tool := range []string{"clang", "codesign"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	out := t.TempDir()
	cmd := exec.Command("sh", "build.sh", out)
	cmd.Dir = "stub"
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build.sh failed: %v\n%s", err, msg)
	}
	built, err := os.ReadFile(filepath.Join(out, "gvx-stub-darwin-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(built, stubImage) {
		t.Fatalf("the embedded stub (%d bytes) differs from a fresh build (%d bytes): run go generate in this package", len(stubImage), len(built))
	}
}

func TestStubImageIsSignedMachO(t *testing.T) {
	// The magic of a 64-bit little-endian Mach-O file.
	if len(stubImage) < 4 || !bytes.Equal(stubImage[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) {
		t.Fatalf("the embedded stub does not start with a Mach-O header: % x", stubImage[:min(4, len(stubImage))])
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "stub")
	if err := os.WriteFile(path, stubImage, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skip("codesign is not installed")
	}
	if msg, err := exec.Command("codesign", "--verify", "--strict", path).CombinedOutput(); err != nil {
		t.Fatalf("codesign --verify: %v\n%s", err, msg)
	}
}

func TestPlatformNameAndErrors(t *testing.T) {
	err := error(&ErrUnavailable{Host: "windows/amd64", Reason: "no toolchain"})
	var u *ErrUnavailable
	if !errors.As(err, &u) || !strings.Contains(err.Error(), "windows/amd64") || !strings.Contains(err.Error(), "no toolchain") {
		t.Fatalf("ErrUnavailable message = %q", err)
	}
}
