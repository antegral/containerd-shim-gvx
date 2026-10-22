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

//go:build darwin || windows || linux

package e2e

import (
	"io"
	"testing"
)

// stdioReopenScript reopens the three standard streams through their device
// and procfs names. Real images do this: nginx logs to /dev/stdout and
// /dev/stderr, and many tools write to /dev/stdout.
const stdioReopenScript = `echo a > /dev/stdout
echo b > /dev/stderr
echo c > /proc/self/fd/1
cat /dev/stdin
exec 3>/dev/stdout 4>/dev/stdout
echo d >&3
exec 3>&-
echo e
echo f >&4
exec 4>&-
echo g`

// TestE2EStdioReopenThroughDeviceNames verifies that a reopen of a standard
// stream creates a new file description on the same host writer or reader.
// Closing one description must leave the others and fd 1 usable.
func TestE2EStdioReopenThroughDeviceNames(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			pr, pw := io.Pipe()
			go func() {
				_, err := io.WriteString(pw, "input-line\n")
				_ = pw.CloseWithError(err)
			}()
			defer func() {
				_ = pr.Close()
			}()
			code, stdout, stderr := runGuest(t, guestSpec{
				plat:  b.plat,
				image: busyboxImage,
				argv:  []string{"sh", "-c", stdioReopenScript},
				stdin: pr,
			})
			if code != 0 {
				t.Fatalf("guest exit code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout, stderr)
			}
			if want := "a\nc\ninput-line\nd\ne\nf\ng\n"; stdout != want {
				t.Errorf("host stdout = %q, want %q", stdout, want)
			}
			if want := "b\n"; stderr != want {
				t.Errorf("host stderr = %q, want %q", stderr, want)
			}
		})
	}
}
