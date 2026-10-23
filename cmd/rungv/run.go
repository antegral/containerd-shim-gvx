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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"z.gfire.dev/gvx/pkg/gvx"
)

func init() {
	register(command{
		name:    "run",
		summary: "Run a command in an OCI image or a Linux ELF64 binary inside the sandbox.",
		usage: []string{
			"rungv run [flags] -image=<oci-image> [-- command args...]",
			"rungv run [flags] -bin=<linux-elf64>",
		},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return runSubcommand(ctx, args, streams.stdin, streams.stdout, streams.stderr)
		},
	})
}

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(val string) error {
	for _, part := range strings.Split(val, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			*m = append(*m, trimmed)
		}
	}
	return nil
}

// runConfig is the parsed result of `rungv run` arguments.
type runConfig struct {
	cfg gvx.Config
	// autoPlatform reports that the user left the backend selection to gvx.
	autoPlatform bool
}

// parseRunArgs converts `rungv run` arguments into a gvx.Config. It returns
// the process exit code when the arguments end the command without a run.
func parseRunArgs(args []string, stdin io.Reader, stdout, stderr io.Writer) (rc runConfig, exitCode int, done bool) {
	fs := flag.NewFlagSet("rungv run", flag.ContinueOnError)
	fs.SetOutput(stderr)

	platformFlag := fs.String("platform", string(gvx.PlatformAuto), "Execution backend: auto, whpx, hvf, or systrap")
	archFlag := fs.String("arch", runtime.GOARCH, "Guest Linux architecture: amd64 or arm64")
	netFlag := fs.String("net", string(gvx.NetModeNAT), "Network backend: nat, wg, or none")
	isolateLANFlag := fs.Bool("isolate-lan", false, "Block RFC1918 and loopback LAN destinations in NAT mode")
	wgConfFlag := fs.String("wg-conf", "", "Path to WireGuard INI configuration file")
	wgConfigAlias := fs.String("wg-config", "", "Alias for -wg-conf")
	imageFlag := fs.String("image", "", "OCI image reference or archive path")
	binFlag := fs.String("bin", "", "Host path to a Linux ELF64 executable")
	workspaceFlag := fs.String("workspace", "", "Host directory mounted at /workspace")
	readOnlyFlag := fs.Bool("ro", false, "Mount /workspace read-only")
	workDirFlag := fs.String("workdir", "", "Initial guest working directory")
	cacheDirFlag := fs.String("cache-dir", "", "EROFS layer cache directory")
	registryURLFlag := fs.String("registry-url", "", "OCI registry base URL")
	lockdownFlag := fs.Bool("lockdown", true, "Lock down the host process before guest entry (RestrictedToken and JobObject, or Seatbelt); use -lockdown=false to opt out")
	ttyFlag := fs.Bool("t", false, "Allocate a pseudo-TTY for guest stdio")
	interactiveFlag := fs.Bool("i", false, "Keep STDIN open")
	itFlag := fs.Bool("it", false, "Allocate an interactive pseudo-TTY for guest stdio")

	var portSpecs multiStringFlag
	fs.Var(&portSpecs, "p", "Publish a container port to the host (hostPort:guestPort[/proto])")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return runConfig{}, 0, true
		}
		return runConfig{}, 2, true
	}

	remaining := fs.Args()
	if len(remaining) > 0 && remaining[0] == "--" {
		remaining = remaining[1:]
	}

	imageRef := strings.TrimSpace(*imageFlag)
	binPath := strings.TrimSpace(*binFlag)
	guestArgv := remaining

	// If neither -image nor -bin was set, treat the first positional argument
	// as an ELF binary path (if it exists on the host with an ELF header) or
	// an OCI image reference.
	if imageRef == "" && binPath == "" && len(guestArgv) > 0 {
		first := guestArgv[0]
		if isHostELFFile(first) {
			binPath = first
			guestArgv = guestArgv[1:]
		} else {
			imageRef = first
			guestArgv = guestArgv[1:]
		}
	}

	if imageRef == "" && binPath == "" {
		_, _ = fmt.Fprintln(stderr, "rungv run: specify -image=<image>, -bin=<elf>, or a positional target")
		return runConfig{}, 2, true
	}

	var portForwards []gvx.PortForward
	for _, spec := range portSpecs {
		pf, err := gvx.ParsePortForward(spec)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "rungv run: %v\n", err)
			return runConfig{}, 2, true
		}
		portForwards = append(portForwards, pf)
	}

	wgConfPath := strings.TrimSpace(*wgConfFlag)
	if wgConfPath == "" {
		wgConfPath = strings.TrimSpace(*wgConfigAlias)
	}

	platform := gvx.PlatformType(strings.ToLower(strings.TrimSpace(*platformFlag)))
	return runConfig{
		autoPlatform: platform == gvx.PlatformAuto,
		cfg: gvx.Config{
			Platform:            platform,
			Architecture:        strings.ToLower(strings.TrimSpace(*archFlag)),
			NetworkMode:         gvx.NetworkMode(strings.ToLower(strings.TrimSpace(*netFlag))),
			IsolateLAN:          *isolateLANFlag,
			PortForwards:        portForwards,
			WireGuardConfigPath: wgConfPath,
			OCIImage:            imageRef,
			OCICacheDir:         strings.TrimSpace(*cacheDirFlag),
			RegistryBaseURL:     strings.TrimSpace(*registryURLFlag),
			BinaryPath:          binPath,
			WorkspacePath:       strings.TrimSpace(*workspaceFlag),
			WorkspaceReadOnly:   *readOnlyFlag,
			Argv:                guestArgv,
			WorkDir:             strings.TrimSpace(*workDirFlag),
			Stdin:               stdin,
			Stdout:              stdout,
			Stderr:              stderr,
			TTY:                 *ttyFlag || *itFlag || *interactiveFlag,
			DisableHostLockdown: !*lockdownFlag,
		},
	}, 0, false
}

func runSubcommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	rc, exitCode, done := parseRunArgs(args, stdin, stdout, stderr)
	if done {
		return exitCode
	}

	sb, err := gvx.New(ctx, rc.cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv run: init sandbox: %v\n", err)
		if errors.Is(err, gvx.ErrInvalidConfig) {
			return 2
		}
		return 1
	}
	defer func() {
		_ = sb.Close()
	}()
	if rc.autoPlatform {
		_, _ = fmt.Fprintf(stderr, "rungv: platform=%s\n", sb.PlatformName())
	}
	if rc.cfg.DisableHostLockdown {
		_, _ = fmt.Fprintln(stderr, "rungv: warning: host lockdown disabled")
	}

	exitCode, err = sb.Run(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv run: %v\n", err)
		if exitCode == 0 {
			return 1
		}
		return exitCode
	}
	return exitCode
}

func isHostELFFile(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer func() {
		_ = f.Close()
	}()
	var hdr [5]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F' && hdr[4] == 2
}
