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

//go:build (darwin || windows) && (amd64 || arm64)

package systrap

import (
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// hasContextFlag reports whether flags selects the component f. Every
// component constant carries the architecture bit, so a flags word without
// the component never matches.
func hasContextFlag(flags, f uint32) bool { return flags&f == f }

func TestStopContextExcludesVectorState(t *testing.T) {
	c := newHostContext()
	c.loadFrom(arch.New(arch.Host), false)
	got := c.u32(ctxOffFlags)
	if got != c.gprFlags() {
		t.Fatalf("flags of a stop without vector state = %#x, want gprFlags %#x", got, c.gprFlags())
	}
	if !hasContextFlag(got, ctxFlagControl) || !hasContextFlag(got, ctxFlagInteger) {
		t.Errorf("flags %#x lack the control or integer component", got)
	}
	if hasContextFlag(got, ctxFlagFloat) {
		t.Errorf("flags %#x select the vector state, which the stop does not use", got)
	}
}

func TestStartContextWithVectorStateSelectsEverything(t *testing.T) {
	c := newHostContext()
	c.loadFrom(arch.New(arch.Host), true)
	got := c.u32(ctxOffFlags)
	if got != c.guestFlags() {
		t.Fatalf("flags of a start with vector state = %#x, want guestFlags %#x", got, c.guestFlags())
	}
	for name, f := range map[string]uint32{"control": ctxFlagControl, "integer": ctxFlagInteger, "float": ctxFlagFloat} {
		if !hasContextFlag(got, f) {
			t.Errorf("flags %#x lack the %s component", got, name)
		}
	}
}

func TestLoadFromReplacesEarlierFlags(t *testing.T) {
	c := newHostContext()
	ac := arch.New(arch.Host)
	c.loadFrom(ac, true)
	c.loadFrom(ac, false)
	if got := c.u32(ctxOffFlags); hasContextFlag(got, ctxFlagFloat) {
		t.Fatalf("flags %#x keep the vector component of the earlier start", got)
	}
}

func TestVectorFetchSelectsOnlyVectorState(t *testing.T) {
	c := newHostContext()
	f := c.fpFlags()
	if !hasContextFlag(f, ctxFlagFloat) {
		t.Errorf("fpFlags %#x lack the float component", f)
	}
	if hasContextFlag(f, ctxFlagControl) || hasContextFlag(f, ctxFlagInteger) {
		t.Errorf("fpFlags %#x also fetch the general-purpose registers", f)
	}
}
