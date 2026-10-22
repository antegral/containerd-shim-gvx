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

//go:build darwin && arm64 && !pagesize_16k

package systrap

import (
	"errors"
	"testing"
)

// TestNewNeedsSixteenKilobytePages checks that a default build refuses to run
// instead of running in a degraded mode.
func TestNewNeedsSixteenKilobytePages(t *testing.T) {
	p, err := New()
	if p != nil {
		_ = p.Close()
		t.Fatal("New succeeded with 4KB guest pages")
	}
	var pe *ErrUnsupportedPageSize
	if !errors.As(err, &pe) {
		t.Fatalf("New error = %v, want *ErrUnsupportedPageSize", err)
	}
	const want = "systrap on darwin/arm64 needs hostarch.PageSize == host VM page size (16KB): build with -tags pagesize_16k"
	if got := err.Error(); len(got) < len(want) || got[:len(want)] != want {
		t.Fatalf("error text = %q, want prefix %q", got, want)
	}
}
