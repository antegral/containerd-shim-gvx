//go:build windows

package aio

// LinuxQueue is an alias for GoQueue on Windows.
type LinuxQueue = GoQueue

// NewLinuxQueue returns a worker-backed Queue on Windows.
func NewLinuxQueue(cap int) (*LinuxQueue, error) {
	return NewGoQueue(cap), nil
}
