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

package systrap

import (
	"runtime"

	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// Platform is the Windows systrap backend. No Windows engine exists, so a
// Platform value never carries state.
type Platform struct {
	platform.Platform
}

// New always fails on Windows.
//
// The engine needs a stub executable that has no Go runtime. Building one
// needs a Windows-targeting C toolchain with a COFF linker (lld-link, or
// MinGW-w64 with the clang or gcc driver). The development host has Apple
// clang 21 and no such linker, so no stub bytes exist that could be verified.
// The Windows stub also needs Job Object confinement and a verified
// NtSetInformationProcess class 40 callback, and none of that has been run.
func New() (*Platform, error) {
	return nil, &ErrUnavailable{
		Host:   "windows/" + runtime.GOARCH,
		Reason: "the stub subprocess needs a Windows C toolchain with a COFF linker (lld-link or MinGW-w64), and this build has none",
	}
}

// Probe always fails on Windows for the reason that New gives.
func Probe() (ProbeInfo, error) {
	_, err := New()
	return ProbeInfo{}, err
}
