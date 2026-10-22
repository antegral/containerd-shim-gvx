//go:build darwin

package sync

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// XNU operation codes from bsd/sys/ulock.h. UL_COMPARE_AND_WAIT keys waiters
// on a 32-bit word of the calling process, which matches Linux FUTEX_PRIVATE.
const (
	ulCompareAndWait = 1
	ulfWakeAll       = 0x100

	// maxUlockTimeoutMicros is the largest timeout that __ulock_wait accepts.
	maxUlockTimeoutMicros = 1<<32 - 1
)

//go:linkname darwinSyscall6 syscall.syscall6
func darwinSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

func ulockWaitTrampoline()
func ulockWakeTrampoline()
func addrOfUlockWait() uintptr
func addrOfUlockWake() uintptr

// libSystem exports both calls without a public header. The signatures are
// int __ulock_wait(uint32_t op, void *addr, uint64_t value, uint32_t timeout_us)
// and int __ulock_wake(uint32_t op, void *addr, uint64_t wake_value).
//
//go:cgo_import_dynamic libc_ulock_wait __ulock_wait "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_ulock_wake __ulock_wake "/usr/lib/libSystem.B.dylib"

// FutexWait parks the caller while *addr equals val.
// A negative timeout blocks without limit. It returns nil after a wake,
// ErrFutexAgain if *addr differs from val, and ErrFutexTimedOut on timeout.
//
// The kernel compares the word again before it parks the thread. A change in
// that window returns nil instead of ErrFutexAgain, so callers re-read the word.
func FutexWait(addr *uint32, val uint32, timeout time.Duration) error {
	if addr == nil {
		return errNilFutexAddr
	}
	if atomic.LoadUint32(addr) != val {
		return ErrFutexAgain
	}
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		// A timeout of zero microseconds means "no timeout" to __ulock_wait,
		// so a bounded wait always passes at least one microsecond.
		var micros uintptr
		if timeout >= 0 {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return ErrFutexTimedOut
			}
			micros = uintptr(min((remaining+time.Microsecond-1)/time.Microsecond, maxUlockTimeoutMicros))
		}
		_, _, errno := darwinSyscall6(addrOfUlockWait(), ulCompareAndWait, uintptr(unsafe.Pointer(addr)), uintptr(val), micros, 0, 0)
		runtime.KeepAlive(addr)
		switch errno {
		case 0:
			return nil
		case syscall.ETIMEDOUT, syscall.EINTR:
			// ETIMEDOUT also fires for a clamped chunk of a very long wait.
			// Looping tests the deadline again, and the kernel compares the word again.
			continue
		default:
			return fmt.Errorf("__ulock_wait: %w", errno)
		}
	}
}

// FutexWake wakes up to count threads parked on addr.
// Each __ulock_wake call wakes one thread and fails with ENOENT when none waits.
// XNU still reports success for a thread that is awake but has not left the
// kernel yet. The result is an upper bound, and it is zero only without waiters.
func FutexWake(addr *uint32, count int) int {
	if addr == nil || count <= 0 {
		return 0
	}
	woken := 0
	for woken < count {
		_, _, errno := darwinSyscall6(addrOfUlockWake(), ulCompareAndWait, uintptr(unsafe.Pointer(addr)), 0, 0, 0, 0)
		runtime.KeepAlive(addr)
		if errno == syscall.ENOENT {
			break
		}
		if errno != 0 {
			// EFAULT and EINVAL mean addr is not a valid aligned word, which is a caller bug.
			panic(fmt.Sprintf("__ulock_wake(%p): %v", addr, errno))
		}
		woken++
	}
	return woken
}

// FutexWakeAll wakes every thread parked on addr.
// XNU does not report how many threads woke, so the result is 1 if any thread
// waited on addr and 0 otherwise.
func FutexWakeAll(addr *uint32) int {
	if addr == nil {
		return 0
	}
	_, _, errno := darwinSyscall6(addrOfUlockWake(), ulCompareAndWait|ulfWakeAll, uintptr(unsafe.Pointer(addr)), 0, 0, 0, 0)
	runtime.KeepAlive(addr)
	switch errno {
	case 0:
		return 1
	case syscall.ENOENT:
		return 0
	default:
		panic(fmt.Sprintf("__ulock_wake(%p, ULF_WAKE_ALL): %v", addr, errno))
	}
}
