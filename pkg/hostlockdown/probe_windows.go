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

package hostlockdown

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/windows"
)

// probeRestrictedOpenBlocked binds the restricted token to a scratch thread
// and opens host paths that the workspace entry does not cover. The kernel
// must answer ERROR_ACCESS_DENIED for each existing path. The probe also
// proves that SetThreadToken accepts the token without a privilege.
//
// The scratch goroutine never unlocks its thread. The runtime ends the thread
// when the goroutine returns, and that drops the impersonation token.
func probeRestrictedOpenBlocked(token windows.Token, workspaceReal string) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.SetThreadToken(nil, token); err != nil {
			result <- fmt.Errorf("hostlockdown: SetThreadToken on probe thread: %w", err)
			return
		}
		result <- openUnlistedPaths(unlistedProbeTargets(workspaceReal))
	}()
	return <-result
}

// unlistedProbeTargets returns existing host locations outside the workspace.
func unlistedProbeTargets(workspaceReal string) []string {
	var targets []string
	if workspaceReal != "" {
		targets = append(targets, filepath.Dir(workspaceReal))
	}
	if home := os.Getenv("USERPROFILE"); home != "" {
		targets = append(targets, home)
	}
	if root := os.Getenv("SystemRoot"); root != "" {
		targets = append(targets, filepath.Join(root, "System32", "drivers", "etc", "hosts"))
	}
	return targets
}

func openUnlistedPaths(paths []string) error {
	var denied int
	for _, p := range paths {
		name, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return fmt.Errorf("hostlockdown: encode probe path %q: %w", p, err)
		}
		h, err := windows.CreateFile(
			name,
			windows.GENERIC_READ,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS,
			0,
		)
		switch {
		case err == nil:
			_ = windows.CloseHandle(h)
			return fmt.Errorf("hostlockdown: restricted token opened unlisted path %q", p)
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			denied++
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		default:
			return fmt.Errorf("hostlockdown: open probe of %q failed for an unrelated reason: %w", p, err)
		}
	}
	if denied == 0 {
		return errors.New("hostlockdown: no probe path exists to verify the restricted token")
	}
	return nil
}
