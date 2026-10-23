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

//go:build arm64

package arch

import (
	"bytes"
	"io"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/cpuid"
)

// A tracer that writes the general registers must not change the thread
// pointer, because the register set has no field for it.
func TestPtraceSetRegsKeepsThreadPointer(t *testing.T) {
	const tls = 0x4206c8
	var set linux.PtraceRegs
	set.Regs[1] = 7
	set.Sp = 0x2000
	set.Pc = 0x1000
	buf := make([]byte, set.SizeBytes())
	set.MarshalBytes(buf)

	for _, tc := range []struct {
		name  string
		write func(*State, io.Reader) (int, error)
	}{
		{"PtraceSetRegs", (*State).PtraceSetRegs},
		{"PtraceSetRegSet", func(s *State, src io.Reader) (int, error) {
			return s.PtraceSetRegSet(_NT_PRSTATUS, src, len(buf), cpuid.FeatureSet{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := New(ARM64)
			ctx.Regs.TPIDR_EL0 = tls
			if _, err := tc.write(&ctx.State, bytes.NewReader(buf)); err != nil {
				t.Fatalf("write registers: %v", err)
			}
			if got := ctx.TLS(); got != tls {
				t.Errorf("TLS() = %#x after the write, want %#x", got, tls)
			}
			if r := ctx.Regs; r.Regs[1] != 7 || r.Sp != 0x2000 || r.Pc != 0x1000 {
				t.Errorf("x1, sp, pc = %#x, %#x, %#x, want 0x7, 0x2000, 0x1000", r.Regs[1], r.Sp, r.Pc)
			}
		})
	}
}
