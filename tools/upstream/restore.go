package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// RestoreUnrequiredEdits rewrites Tier 3 files to their upstream bytes when they differ only
// by a build constraint or formatting edit that the allowlist does not require.
//
// Content edits are never touched: a file whose canonical form differs from upstream stays as is.
// Run RetagFiles afterwards to re-apply the edits that the allowlist does require.
func RestoreUnrequiredEdits(cfg AuditConfig) (int, error) {
	restored := 0
	err := walkRepo(cfg.RootDir, func(abs, relSlash string, d fs.DirEntry) error {
		if !isGoSource(relSlash) || ClassifyFile(relSlash) != Tier3Upstream {
			return nil
		}
		upBytes, ok := cfg.Upstream.pristine(relSlash)
		if !ok {
			return nil
		}
		repoBytes, err := os.ReadFile(abs)
		if err != nil {
			return fmt.Errorf("read %s: %w", relSlash, err)
		}
		rule, hasRule := cfg.Patches.Lookup(relSlash)
		_, classErr := classifyAgainstUpstream(compareInput{
			relSlash: relSlash, repo: repoBytes, upstream: upBytes, rule: rule, hasRule: hasRule,
		})
		if classErr == nil || !isRestorable(classErr) {
			return nil
		}
		if !bytes.Equal(canonicalForm(relSlash, repoBytes), canonicalForm(relSlash, upBytes)) {
			return nil
		}
		if err := writeFileAtomic(abs, upBytes, d); err != nil {
			return err
		}
		restored++
		return nil
	})
	return restored, err
}

func isRestorable(err error) bool {
	for _, target := range []error{errUnlistedBuildTag, errRedundantPatch, errLinuxFileModified, errNonGeneratedFmt, errPatchMismatch} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
