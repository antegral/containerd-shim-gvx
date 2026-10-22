//go:build linux || darwin || windows

package sync

import (
	"errors"
	"syscall"
)

// FutexWait, FutexWake and FutexWakeAll expose the host's native word-wait primitive.
// Linux uses futex(2), macOS uses __ulock_wait, and Windows uses WaitOnAddress.
// All three park the calling thread inside the kernel while a 32-bit word equals an expected value.
//
// Callers MUST pass the address of a heap or global word and MUST store the new
// value before they call FutexWake. A nil error from FutexWait means the thread
// woke or the word changed, so callers re-read the word.
//
// FutexWake and FutexWakeAll return the number of woken threads. Linux reports it
// exactly. XNU and Windows do not report it. On those hosts the result is an upper
// bound, and it is zero only when no thread waited on the word.
var (
	// ErrFutexAgain reports that the word at the address did not equal the expected value.
	ErrFutexAgain = syscall.EAGAIN

	// ErrFutexTimedOut reports that FutexWait exceeded its timeout.
	ErrFutexTimedOut = syscall.ETIMEDOUT

	errNilFutexAddr = errors.New("futex address is nil")
)
