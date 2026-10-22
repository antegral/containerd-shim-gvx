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

//go:build !darwin && !windows

package gvx

import (
	"fmt"
	"runtime"

	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// openSystrap reports that hosts other than Windows and macOS have no gvx
// systrap engine. Linux uses the upstream runsc systrap platform.
func openSystrap() (platform.Platform, string, error) {
	return nil, "", fmt.Errorf("%w: the %q backend of gvx runs on windows and darwin, not %s", ErrPlatformUnavailable, PlatformSystrap, runtime.GOOS)
}

// probeStub reports that this host has no gvx systrap engine.
func probeStub() (StubInfo, error) {
	_, _, err := openSystrap()
	return StubInfo{}, err
}
