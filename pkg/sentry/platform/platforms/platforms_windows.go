//go:build windows

package platforms

import (
	// Register the Windows Hypervisor Platform backend.
	_ "z.gfire.dev/gvx/pkg/sentry/platform/whpx"
)
