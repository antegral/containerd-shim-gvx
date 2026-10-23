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
	"runtime"
	"strings"

	"z.gfire.dev/gvx/pkg/gvx"
)

func init() {
	register(command{
		name:    "pull",
		summary: "Download an OCI image into the EROFS layer cache.",
		usage:   []string{"rungv pull [flags] <oci-image-or-archive>"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return pullSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

func pullSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rungv pull", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cacheDirFlag := fs.String("cache-dir", "", "EROFS layer cache directory")
	registryURLFlag := fs.String("registry-url", "", "OCI registry base URL")
	archFlag := fs.String("arch", runtime.GOARCH, "Target Linux architecture (amd64 or arm64)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		_, _ = fmt.Fprintln(stderr, "rungv pull: missing <image-or-archive> argument")
		return 2
	}
	target := remaining[0]

	cache, err := gvx.NewLayerCache(strings.TrimSpace(*cacheDirFlag))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", err)
		return 1
	}

	resolved, resolveErr := gvx.ResolveImage(ctx, cache, strings.TrimSpace(*registryURLFlag), target, *archFlag)
	if resolveErr != nil {
		_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", resolveErr)
		return 1
	}
	layerCount := len(resolved.LayerDigests)
	if closeErr := resolved.Close(); closeErr != nil {
		_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", closeErr)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "pulled %s (%d EROFS layers cached in %s)\n", target, layerCount, cache.Dir())
	return 0
}
