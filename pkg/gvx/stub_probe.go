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

package gvx

import (
	"context"
	"time"
)

// StubInfo describes the systrap stub that ProbeStub started, handshook with,
// and stopped again.
type StubInfo struct {
	// Arch is the guest architecture that the stub runs, such as "arm64".
	Arch string
	// HostPageSize is the host VM page size that the stub reported.
	HostPageSize int
	// PID is the host process ID of the template stub.
	PID int
	// ProtocolVersion is the Sentry and stub handoff protocol version.
	ProtocolVersion uint32
	// RoundTrip is the mean time of one guest system call round trip.
	RoundTrip time.Duration
}

// ProbeStub spawns the systrap stub, completes the handshake, measures one
// guest system call round trip, and stops the stub. It returns the same
// errors as New with PlatformSystrap: ErrPlatformUnavailable when the host has
// no engine, or the engine error such as a page-size mismatch. The context
// bounds the wait for the probe to start; the probe itself has fixed timeouts.
func ProbeStub(ctx context.Context) (StubInfo, error) {
	if err := ctx.Err(); err != nil {
		return StubInfo{}, err
	}
	return probeStub()
}
