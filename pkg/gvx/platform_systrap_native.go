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

//go:build darwin || windows

package gvx

import (
	"errors"
	"fmt"

	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/systrap"
)

// openSystrap spawns the systrap stub. New calls it before the host lockdown,
// because the lockdown forbids new processes. A host without an engine
// reports ErrPlatformUnavailable together with the engine error.
func openSystrap() (platform.Platform, string, error) {
	p, err := systrap.New()
	if err != nil {
		return nil, "", systrapError(err)
	}
	return p, systrap.PlatformName, nil
}

// probeStub runs systrap.Probe and maps its result and errors like openSystrap.
func probeStub() (StubInfo, error) {
	info, err := systrap.Probe()
	if err != nil {
		return StubInfo{}, systrapError(err)
	}
	return StubInfo{
		Arch:            info.Arch,
		HostPageSize:    info.PageSize,
		PID:             info.StubPID,
		ProtocolVersion: info.ProtocolVersion,
		RoundTrip:       info.RoundTrip,
	}, nil
}

// systrapError adds ErrPlatformUnavailable to an engine error that reports a
// host without an engine.
func systrapError(err error) error {
	var unavailable *systrap.ErrUnavailable
	if errors.As(err, &unavailable) {
		err = fmt.Errorf("%w: %w", ErrPlatformUnavailable, err)
	}
	return fmt.Errorf("gvx: %s backend: %w", systrap.PlatformName, err)
}
