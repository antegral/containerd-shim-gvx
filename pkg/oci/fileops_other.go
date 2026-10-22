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

//go:build !windows

package oci

import "os"

// A POSIX rename replaces a file that another process holds open, and an open
// file never blocks a delete, so the plain calls suffice.

func openShared(path string) (*os.File, error) { return os.Open(path) }

func readFileShared(path string) ([]byte, error) { return os.ReadFile(path) }

func replaceFile(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }
