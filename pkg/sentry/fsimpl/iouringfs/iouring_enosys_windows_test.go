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

package iouringfs

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

func TestIOUringEnosysOnWindows(t *testing.T) {
	var params linux.IOUringParams
	if _, err := Setup(16, &params); !linuxerr.Equals(linuxerr.ENOSYS, err) {
		t.Fatalf("Setup err = %v, want ENOSYS", err)
	}
	if _, err := Enter(0, 1, 1, 0); !linuxerr.Equals(linuxerr.ENOSYS, err) {
		t.Fatalf("Enter err = %v, want ENOSYS", err)
	}
	if err := Register(0, 0, 0, 0); !linuxerr.Equals(linuxerr.ENOSYS, err) {
		t.Fatalf("Register err = %v, want ENOSYS", err)
	}
}
