//go:build darwin

package hostfd

const (
	// MaxReadWriteIov is UIO_MAXIOV on Darwin.
	MaxReadWriteIov = 1024

	// MaxSendRecvMsgIov is UIO_MAXIOV on Darwin.
	MaxSendRecvMsgIov = 1024
)
