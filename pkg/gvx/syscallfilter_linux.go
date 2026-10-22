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

//go:build linux

package gvx

import (
	"math"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/seccomp"
	"z.gfire.dev/gvx/runsc/boot/filter/config"
)

// syscallFilter returns the function that installs the seccomp program of the
// Sentry on every thread of the process. The program is the one that runsc
// builds for the Sentry: an allowlist, where every other system call kills the
// process. The options follow the config of the Sandbox. The platform adds its
// own rules, and NAT adds the host socket rules of hostinet. A workspace adds
// the rules of the host filesystem, which allow opens relative to a directory
// descriptor only.
func (s *Sandbox) syscallFilter() func() error {
	return func() error {
		opt := config.Options{
			Platform:       s.plat.SeccompInfo(),
			HostNetwork:    s.cfg.NetworkMode == NetModeNAT,
			HostFilesystem: s.cfg.WorkspacePath != "",
			// gvx has no control server. No descriptor has this number.
			ControllerFD: math.MaxUint32,
		}
		rules, denyRules := config.Rules(opt)
		rules.Merge(embedderRules(s.cfg))

		seccompOpts := config.SeccompOptions(opt)
		if seccompLogOnly {
			seccompOpts.DefaultAction = seccomp.Log
		}
		program := &seccomp.Program{
			RuleSets: []seccomp.RuleSet{
				{Rules: denyRules},
				{Rules: rules, Action: seccomp.Allow},
				// The calls that hostlockdown probes, and the calls that code
				// in the embedding process may try, return EPERM. The Sentry
				// kills the process for them, but a Go program that embeds gvx
				// expects an error from os/exec or os.Open.
				{Rules: rejectedRules(), Action: seccomp.ReturnError.Code(uint16(unix.EPERM))},
			},
			Options: seccompOpts,
		}
		return program.Install(nil)
	}
}

// rejectedRules lists the calls that return EPERM when no allow rule matches.
func rejectedRules() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_EXECVE:   seccomp.MatchAll{},
		unix.SYS_EXECVEAT: seccomp.MatchAll{},
		unix.SYS_CLONE:    seccomp.MatchAll{},
		unix.SYS_CLONE3:   seccomp.MatchAll{},
		unix.SYS_OPENAT:   seccomp.MatchAll{},
		unix.SYS_OPENAT2:  seccomp.MatchAll{},
		unix.SYS_SOCKET:   seccomp.MatchAll{},
	}).Merge(archRejectedRules())
}

// embedderRules lists the host calls that gvx makes beyond the Sentry of runsc.
// The Sentry in runsc runs in its own process with a gofer and the control
// server. The Sentry in gvx runs in the host process and reaches the host
// through Go packages.
func embedderRules(cfg Config) seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{})
}
