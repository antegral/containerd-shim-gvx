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

//go:build darwin

package ring0

import (
	"sync/atomic"
	"unsafe"
)

// BluepillExitReason identifies why the in-partition Ring-0 / EL1 stub exited to Sentry.
type BluepillExitReason uint32

const (
	// BluepillExitNone indicates no exit has occurred.
	BluepillExitNone BluepillExitReason = 0
	// BluepillExitSyscall indicates a guest SYSCALL (amd64) or SVC #0 (arm64) trap.
	BluepillExitSyscall BluepillExitReason = 1
	// BluepillExitPageFault indicates a guest page fault (#PF or Data/Instruction Abort).
	BluepillExitPageFault BluepillExitReason = 2
	// BluepillExitInterrupt indicates an asynchronous preemption interrupt.
	BluepillExitInterrupt BluepillExitReason = 3
	// BluepillExitException indicates a synchronous guest exception (e.g., #UD, #GP, BRK).
	BluepillExitException BluepillExitReason = 4
)

// BluepillCommPage is the 4KB shared communication page mapped between the
// hypervisor guest stub and the Go Sentry thread on macOS.
type BluepillCommPage struct {
	Regs             [31]uint64
	SP               uint64
	PC               uint64
	PstateOrRflags   uint64
	TLS              uint64
	FaultAddr        uint64
	FaultCode        uint64
	Vector           uint64
	ExitReason       uint32
	PendingInterrupt uint32
	TLSUpdated       uint32
	_                [3780]byte
}

// OverlayBluepillCommPage casts a 4KB-aligned shared slice to a BluepillCommPage.
func OverlayBluepillCommPage(page []byte) *BluepillCommPage {
	if len(page) < int(unsafe.Sizeof(BluepillCommPage{})) {
		return nil
	}
	return (*BluepillCommPage)(unsafe.Pointer(&page[0]))
}

// SetPendingInterrupt atomically marks an asynchronous interrupt pending on the shared page.
func (c *BluepillCommPage) SetPendingInterrupt() {
	atomic.StoreUint32(&c.PendingInterrupt, 1)
}

// ConsumePendingInterrupt atomically clears and reports whether an interrupt was pending.
func (c *BluepillCommPage) ConsumePendingInterrupt() bool {
	return atomic.SwapUint32(&c.PendingInterrupt, 0) != 0
}
