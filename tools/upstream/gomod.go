package main

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// xArchModule is the disassembler module that SPEC section 3.3 requires for the systrap patchers.
// Upstream gVisor does not depend on it, so gvx owns the pin.
const xArchModule = "golang.org/x/arch"

var errMissingXArch = errors.New("go.mod has no golang.org/x/arch requirement in upstream or in the local file")

// MergeGoMod merges the upstream go.mod with the local one.
//
// Upstream wins for shared requirements unless the local file pins a higher version.
// Local-only requirements and replace directives survive. The module path stays local.
// The golang.org/x/arch pin comes from upstream when upstream lists it, otherwise from the local file.
// A nil or empty local file yields the upstream file with the gvx module path.
func MergeGoMod(upstream, local []byte) ([]byte, error) {
	up, err := modfile.Parse("upstream/go.mod", upstream, nil)
	if err != nil {
		return nil, fmt.Errorf("parse upstream go.mod: %w", err)
	}
	modulePath := targetModulePath
	var loc *modfile.File
	if len(bytes.TrimSpace(local)) > 0 {
		loc, err = modfile.Parse("go.mod", local, nil)
		if err != nil {
			return nil, fmt.Errorf("parse local go.mod: %w", err)
		}
		if loc.Module != nil {
			modulePath = loc.Module.Mod.Path
		}
	}
	if err := up.AddModuleStmt(modulePath); err != nil {
		return nil, fmt.Errorf("set module path: %w", err)
	}

	if loc != nil {
		if err := mergeRequires(up, loc); err != nil {
			return nil, err
		}
		if err := mergeDirectives(up, loc); err != nil {
			return nil, err
		}
	}

	hasArch := slices.ContainsFunc(up.Require, func(r *modfile.Require) bool { return r.Mod.Path == xArchModule })
	if !hasArch {
		return nil, errMissingXArch
	}
	up.Cleanup()
	out, err := up.Format()
	if err != nil {
		return nil, fmt.Errorf("format merged go.mod: %w", err)
	}
	return out, nil
}

type requireState struct {
	version  string
	indirect bool
}

func mergeRequires(up, loc *modfile.File) error {
	merged := make(map[string]requireState, len(up.Require)+len(loc.Require))
	order := make([]string, 0, len(up.Require)+len(loc.Require))
	for _, r := range up.Require {
		if _, dup := merged[r.Mod.Path]; !dup {
			order = append(order, r.Mod.Path)
		}
		merged[r.Mod.Path] = requireState{version: r.Mod.Version, indirect: r.Indirect}
	}
	for _, r := range loc.Require {
		cur, shared := merged[r.Mod.Path]
		if !shared {
			order = append(order, r.Mod.Path)
			merged[r.Mod.Path] = requireState{version: r.Mod.Version, indirect: r.Indirect}
			continue
		}
		next := cur
		if semver.Compare(r.Mod.Version, cur.version) > 0 {
			next.version = r.Mod.Version
		}
		next.indirect = cur.indirect && r.Indirect
		merged[r.Mod.Path] = next
	}
	slices.Sort(order)
	list := make([]*modfile.Require, 0, len(order))
	for _, p := range order {
		st := merged[p]
		list = append(list, &modfile.Require{Mod: module.Version{Path: p, Version: st.version}, Indirect: st.indirect})
	}
	up.SetRequireSeparateIndirect(list)
	return nil
}

func mergeDirectives(up, loc *modfile.File) error {
	if loc.Go != nil && (up.Go == nil || semver.Compare("v"+loc.Go.Version, "v"+up.Go.Version) > 0) {
		if err := up.AddGoStmt(loc.Go.Version); err != nil {
			return fmt.Errorf("set go directive: %w", err)
		}
	}
	if loc.Toolchain != nil && (up.Toolchain == nil || semver.Compare("v"+strings.TrimPrefix(loc.Toolchain.Name, "go"), "v"+strings.TrimPrefix(up.Toolchain.Name, "go")) > 0) {
		if err := up.AddToolchainStmt(loc.Toolchain.Name); err != nil {
			return fmt.Errorf("set toolchain directive: %w", err)
		}
	}
	for _, r := range loc.Replace {
		if err := up.AddReplace(r.Old.Path, r.Old.Version, r.New.Path, r.New.Version); err != nil {
			return fmt.Errorf("keep local replace of %s: %w", r.Old.Path, err)
		}
	}
	return nil
}

// MergeGoSum returns the sorted union of the lines of two go.sum files.
func MergeGoSum(upstream, local []byte) []byte {
	seen := make(map[string]struct{})
	var lines []string
	for _, src := range [][]byte{upstream, local} {
		for line := range strings.Lines(string(src)) {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, dup := seen[line]; dup {
				continue
			}
			seen[line] = struct{}{}
			lines = append(lines, line)
		}
	}
	slices.Sort(lines)
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}
