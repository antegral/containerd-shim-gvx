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
	"errors"
	"fmt"
)

// ErrUnsupportedELFLayout marks an executable whose load segments cannot map
// with the guest page size. Callers separate it from other start failures
// with errors.Is.
var ErrUnsupportedELFLayout = errors.New("gvx: the executable layout does not fit the guest page size")

const (
	// basePageSize is the guest page size of a build without a larger page tag.
	// Linkers align segments to at least this size, so the layout check has
	// nothing to find at this size.
	basePageSize = 4096
)

// elfLayoutProblem describes the first load segment of an ELF64 executable
// that a guest page of pageSize bytes cannot map. It returns an empty string
// when every segment maps, and for a file that is not ELF64. The loader maps
// whole pages, so a segment with an address and a file offset that differ
// modulo the page size fails. Two segments that share one page do not fail.
// The loader gives that page the union of their permissions, and the systrap
// engine runs the code in it.
func elfLayoutProblem(header []byte, pageSize uint64) string {
	_, segments, ok := parseLoadSegments(header)
	if !ok || pageSize == 0 {
		return ""
	}
	for _, seg := range segments {
		if seg.vaddr%pageSize != seg.offset%pageSize {
			return fmt.Sprintf("program header %d (PT_LOAD, vaddr %#x, offset %#x) is not congruent modulo the %d-byte guest page size",
				seg.index, seg.vaddr, seg.offset, pageSize)
		}
	}
	return ""
}

// checkELFLayout returns ErrUnsupportedELFLayout, with the problem and the way
// out, when the executable at execPath cannot load with a guest page of
// pageSize bytes. It returns nil for a file that it cannot read. It also
// returns nil when Config.DisableELFLayoutCheck is set or the page size is the
// base size. The start of the guest process reports an unreadable file.
func (s *Sandbox) checkELFLayout(read func(path string, maxBytes int) ([]byte, error), execPath string, pageSize uint64) error {
	if s.cfg.DisableELFLayoutCheck || pageSize <= basePageSize {
		return nil
	}
	header, err := read(execPath, elfProbeBytes)
	if err != nil || header == nil {
		return nil
	}
	problem := elfLayoutProblem(header, pageSize)
	if problem == "" {
		return nil
	}
	return fmt.Errorf("%w: %q: %s; relink the executable with -z max-page-size=%d, or use a build with 4KB guest pages (no -tags pagesize_16k)",
		ErrUnsupportedELFLayout, execPath, problem, pageSize)
}
