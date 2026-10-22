//go:build darwin

package aio

// LinuxQueue is an alias for GoQueue on macOS.
type LinuxQueue = GoQueue

// NewLinuxQueue returns a worker-backed Queue on macOS.
func NewLinuxQueue(cap int) (*LinuxQueue, error) {
	return NewGoQueue(cap), nil
}
