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

//go:build !windows

package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/creack/pty"
)

// openTerminal returns the slave side of a new pseudo terminal.
func openTerminal(t *testing.T) *os.File {
	t.Helper()
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo terminal on this host: %v", err)
	}
	t.Cleanup(func() {
		_ = tty.Close()
		_ = ptmx.Close()
	})
	return tty
}

func TestSaveRefusesToWriteAnArchiveToATerminal(t *testing.T) {
	tty := openTerminal(t)
	env := newCLIEnv(t)
	var stderr bytes.Buffer
	code := executeCLI(context.Background(), []string{"save", "-cache-dir", env.cacheDir, "alpine"}, nil, tty, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "terminal") {
		t.Errorf("save to a terminal = (%d, %q), want exit 2 and a message about the terminal", code, stderr.String())
	}
}

func TestLoginReadsThePasswordFromATerminalWithoutEchoingIt(t *testing.T) {
	tty := openTerminal(t)
	registry := basicRegistry(t, "alice", "s3cret")
	t.Setenv("DOCKER_CONFIG", t.TempDir())

	var fd int
	oldRead := readTerminalPassword
	readTerminalPassword = func(got int) ([]byte, error) {
		fd = got
		return []byte("s3cret"), nil
	}
	t.Cleanup(func() { readTerminalPassword = oldRead })

	var stdout, stderr bytes.Buffer
	code := executeCLI(context.Background(), []string{"login", "-u", "alice", registry.URL}, tty, &stdout, &stderr)
	if code != 0 || strings.TrimSpace(stdout.String()) != "Login Succeeded" {
		t.Fatalf("login = (%d, %q, %q), want Login Succeeded", code, stdout.String(), stderr.String())
	}
	if fd != int(tty.Fd()) {
		t.Errorf("the password came from file descriptor %d, want the terminal %d", fd, tty.Fd())
	}
	if !strings.Contains(stderr.String(), "Password:") || strings.Contains(stdout.String()+stderr.String(), "s3cret") {
		t.Errorf("prompt output = %q, want a password prompt on stderr that does not show the secret", stderr.String())
	}
}
