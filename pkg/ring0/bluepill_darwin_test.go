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
	"testing"
	"unsafe"
)

func TestBluepillCommPageDarwinLayout(t *testing.T) {
	if got := unsafe.Sizeof(BluepillCommPage{}); got != 4096 {
		t.Fatalf("sizeof(BluepillCommPage) = %d, want 4096", got)
	}
	buf := make([]byte, 4096)
	comm := OverlayBluepillCommPage(buf)
	if comm == nil {
		t.Fatal("OverlayBluepillCommPage returned nil")
	}
	comm.SetPendingInterrupt()
	if !comm.ConsumePendingInterrupt() {
		t.Fatal("ConsumePendingInterrupt returned false, want true")
	}
	if comm.ConsumePendingInterrupt() {
		t.Fatal("second ConsumePendingInterrupt returned true, want false")
	}
}
