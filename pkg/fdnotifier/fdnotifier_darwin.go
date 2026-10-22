//go:build darwin

package fdnotifier

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/waiter"
)

type fdInfo struct {
	queue   *waiter.Queue
	waiting bool
}

type notifier struct {
	pauseMu sync.Mutex
	mu      sync.Mutex
	fdMap   map[int32]*fdInfo
}

var shared struct {
	notifier *notifier
	once     sync.Once
}

func ensureSharedNotifier() {
	shared.once.Do(func() {
		shared.notifier = &notifier{
			fdMap: make(map[int32]*fdInfo),
		}
	})
}

// AddFD adds an FD to the list of observed FDs.
func AddFD(fd int32, queue *waiter.Queue) error {
	ensureSharedNotifier()
	n := shared.notifier
	n.mu.Lock()
	defer n.mu.Unlock()

	if _, ok := n.fdMap[fd]; ok {
		panic(fmt.Sprintf("File descriptor %v added twice", fd))
	}
	n.fdMap[fd] = &fdInfo{
		queue:   queue,
		waiting: queue != nil && queue.Events() != 0,
	}
	return nil
}

// UpdateFD updates the set of events the fd needs to be notified on.
func UpdateFD(fd int32) error {
	ensureSharedNotifier()
	n := shared.notifier
	n.mu.Lock()
	defer n.mu.Unlock()

	if fi, ok := n.fdMap[fd]; ok && fi.queue != nil {
		fi.waiting = fi.queue.Events() != 0
	}
	return nil
}

// RemoveFD removes an FD from the list of observed FDs.
func RemoveFD(fd int32) {
	ensureSharedNotifier()
	n := shared.notifier
	n.mu.Lock()
	defer n.mu.Unlock()

	delete(n.fdMap, fd)
}

// HasFD returns true if the FD is in the list of observed FDs.
func HasFD(fd int32) bool {
	ensureSharedNotifier()
	n := shared.notifier
	n.mu.Lock()
	defer n.mu.Unlock()

	_, ok := n.fdMap[fd]
	return ok
}

// Pause suspends notifications until Resume is called.
func Pause() {
	ensureSharedNotifier()
	shared.notifier.pauseMu.Lock()
}

// Resume ends the effect of a previous call to Pause.
func Resume() {
	ensureSharedNotifier()
	shared.notifier.pauseMu.Unlock()
}

// NonBlockingPoll polls the given FD in non-blocking fashion.
func NonBlockingPoll(fd int32, mask waiter.EventMask) waiter.EventMask {
	e := struct {
		fd      int32
		events  int16
		revents int16
	}{
		fd:     fd,
		events: int16(mask.ToLinux()),
	}
	for {
		n, _, err := unix.RawSyscall(unix.SYS_POLL, uintptr(unsafe.Pointer(&e)), 1, 0)
		if err == unix.EINTR {
			continue
		}
		if err != 0 {
			return mask
		}
		if n == 0 {
			return 0
		}
		return waiter.EventMaskFromLinux(uint32(e.revents))
	}
}
