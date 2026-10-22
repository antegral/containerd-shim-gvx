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

package hvf

// x86CommPage is the page that the Ring-0 stub and the Sentry share on x86.
// The stub reaches it through GS after SWAPGS. The interrupt frame lives on
// the kernel stack page that follows the CommPage, so the stub never copies
// the frame.
type x86CommPage struct {
	// Regs holds RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15 in hardware
	// register order. The RSP slot stays unused: the frame holds the user stack
	// pointer.
	Regs [16]uint64 // 0
	// Scratch holds the user stack pointer while SYSCALL switches stacks.
	Scratch uint64 // 128
	// Stack is the kernel stack top that SYSCALL loads into RSP.
	Stack uint64 // 136
	// CR2 is the faulting address of a page fault.
	CR2 uint64 // 144
	_   [13]uint64
	// TSS is the 64-bit task state segment: RSP0 tells the CPU where an
	// exception from user mode pushes its frame.
	TSS [104]byte // 256
	_   [3736]byte
}

// x86 stack page: the CPU and the stub build the interrupt frame at the top,
// growing down. Offsets are bytes from the start of the stack page.
const (
	x86StackPageSize = 4096
	x86FrameVector   = x86StackPageSize - 56 // Pushed by the stub.
	x86FrameErrCode  = x86StackPageSize - 48 // Pushed by the CPU or by the stub.
	x86FrameRIP      = x86StackPageSize - 40
	x86FrameCS       = x86StackPageSize - 32
	x86FrameRFLAGS   = x86StackPageSize - 24
	x86FrameRSP      = x86StackPageSize - 16
	x86FrameSS       = x86StackPageSize - 8
)
