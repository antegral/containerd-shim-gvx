//go:build windows

package hostfd

const (
	// MaxReadWriteIov is UIO_MAXIOV on Windows.
	MaxReadWriteIov = 1024

	// MaxSendRecvMsgIov is UIO_MAXIOV on Windows.
	MaxSendRecvMsgIov = 1024
)
