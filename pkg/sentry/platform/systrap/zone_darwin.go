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

//go:build darwin && arm64

package systrap

import "os"

// ZoneEnv names the environment variable that turns the zone mode on. The mode
// is a prototype. It lets a guest run an executable that links below 4GB, and
// it moves every other mapping of the guest above the biased zone.
const ZoneEnv = "GVX_SYSTRAP_FIXED_IMAGES"

// zoneModeRequested reports whether the environment turns the zone mode on.
func zoneModeRequested() bool { return os.Getenv(ZoneEnv) == "1" }
