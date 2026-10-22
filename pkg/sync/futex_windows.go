//go:build windows

package sync

import (
	"fmt"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modSynch             = windows.NewLazySystemDLL("api-ms-win-core-synch-l1-2-0.dll")
	procWaitOnAddress    = modSynch.NewProc("WaitOnAddress")
	procWakeByAddrSingle = modSynch.NewProc("WakeByAddressSingle")
	procWakeByAddrAll    = modSynch.NewProc("WakeByAddressAll")
)

// maxWaitMillis is the largest finite WaitOnAddress timeout. The value
// INFINITE (0xFFFFFFFF) selects an unbounded wait, so it cannot be a bounded chunk.
const maxWaitMillis = windows.INFINITE - 1

// futexWaiterShards spreads the waiter counters over independent locks.
const futexWaiterShards = 64

// futexWaiters counts the threads parked per address. WakeByAddress* does not
// report how many threads it woke. FutexWake uses these counters to wake
// no more than the requested number of threads and to report an upper bound.
var futexWaiters [futexWaiterShards]struct {
	mu      Mutex
	waiters map[*uint32]int
}

func futexShard(addr *uint32) int {
	return int(uintptr(unsafe.Pointer(addr))>>2) % futexWaiterShards
}

func futexAddWaiter(addr *uint32, delta int) int {
	s := &futexWaiters[futexShard(addr)]
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waiters == nil {
		s.waiters = make(map[*uint32]int)
	}
	n := s.waiters[addr] + delta
	if n <= 0 {
		delete(s.waiters, addr)
		return 0
	}
	s.waiters[addr] = n
	return n
}

func futexWaiterCount(addr *uint32) int {
	s := &futexWaiters[futexShard(addr)]
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.waiters[addr]
}

// FutexWait parks the caller while *addr equals val.
// A negative timeout blocks without limit. It returns nil after a wake,
// ErrFutexAgain if *addr differs from val, and ErrFutexTimedOut on timeout.
func FutexWait(addr *uint32, val uint32, timeout time.Duration) error {
	if addr == nil {
		return errNilFutexAddr
	}
	if atomic.LoadUint32(addr) != val {
		return ErrFutexAgain
	}
	// The waiter registers before it calls WaitOnAddress. A waker that stored a new
	// value before FutexWake either sees the registration or WaitOnAddress sees the new value.
	futexAddWaiter(addr, 1)
	defer futexAddWaiter(addr, -1)

	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	compareVal := val
	for {
		millis := uint32(windows.INFINITE)
		if timeout >= 0 {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return ErrFutexTimedOut
			}
			millis = uint32(min((remaining+time.Millisecond-1)/time.Millisecond, maxWaitMillis))
		}
		r1, _, e1 := procWaitOnAddress.Call(
			uintptr(unsafe.Pointer(addr)),
			uintptr(unsafe.Pointer(&compareVal)),
			unsafe.Sizeof(compareVal),
			uintptr(millis),
		)
		if r1 != 0 {
			return nil
		}
		if e1 != syscall.Errno(windows.ERROR_TIMEOUT) {
			return fmt.Errorf("WaitOnAddress: %w", e1)
		}
		// ERROR_TIMEOUT also marks a clamped chunk of a very long wait.
		// The loop tests the deadline again.
	}
}

// FutexWake wakes up to count threads parked on addr.
// WakeByAddressSingle does not report whether a thread woke, so the result is
// the number of wake calls issued for registered waiters. It is an upper bound.
// A waiter that already woke but has not deregistered yet still counts.
func FutexWake(addr *uint32, count int) int {
	if addr == nil || count <= 0 {
		return 0
	}
	n := min(count, futexWaiterCount(addr))
	for range n {
		procWakeByAddrSingle.Call(uintptr(unsafe.Pointer(addr)))
	}
	return n
}

// FutexWakeAll wakes every thread parked on addr. It returns the number of
// registered waiters at the time of the call, which is an upper bound.
func FutexWakeAll(addr *uint32) int {
	if addr == nil {
		return 0
	}
	n := futexWaiterCount(addr)
	if n > 0 {
		procWakeByAddrAll.Call(uintptr(unsafe.Pointer(addr)))
	}
	return n
}
