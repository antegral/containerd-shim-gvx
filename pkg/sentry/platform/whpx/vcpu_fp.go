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

package whpx

// readFP reads the floating-point and vector registers of the processor into
// image. The processor must not run.
func (v *vcpu) readFP(image []byte) error {
	b := v.regs
	b.reset()
	if v.p.arm64 {
		a64WantFP(b)
	} else {
		x86WantFP(b)
	}
	if err := v.p.be.getRegs(v.index, b); err != nil {
		return err
	}
	if v.p.arm64 {
		return a64FPFromRegs(image, b, 0)
	}
	return x86FXSaveFromRegs(image, b, 0)
}

// writeFP loads image into the floating-point and vector registers of the
// processor. The processor must not run.
func (v *vcpu) writeFP(image []byte) error {
	b := v.regs
	b.reset()
	var err error
	if v.p.arm64 {
		err = a64FPToRegs(b, image)
	} else {
		err = x86FXSaveToRegs(b, image)
	}
	if err != nil {
		return err
	}
	return v.p.be.setRegs(v.index, b)
}
