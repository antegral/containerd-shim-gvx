//go:build windows

package fdnotifier

import "z.gfire.dev/gvx/pkg/waiter"

// NonBlockingPoll reports every requested event as ready. Windows has no
// descriptor poll that fits a host handle, so a caller that needs a real
// answer tries the operation and handles its error.
func NonBlockingPoll(_ int32, mask waiter.EventMask) waiter.EventMask {
	return mask
}
