//go:build darwin || windows

package fdnotifier

import (
	"testing"

	"z.gfire.dev/gvx/pkg/waiter"
)

func TestTableTracksObservedFDs(t *testing.T) {
	const fd = 1 << 20 // No host descriptor: the table only keys on the number.
	var q waiter.Queue
	if HasFD(fd) {
		t.Fatalf("HasFD(%d) = true before AddFD", fd)
	}
	if err := AddFD(fd, &q); err != nil {
		t.Fatalf("AddFD: %v", err)
	}
	t.Cleanup(func() { RemoveFD(fd) })
	if !HasFD(fd) {
		t.Errorf("HasFD(%d) = false after AddFD", fd)
	}
	if err := UpdateFD(fd); err != nil {
		t.Errorf("UpdateFD: %v", err)
	}
	RemoveFD(fd)
	if HasFD(fd) {
		t.Errorf("HasFD(%d) = true after RemoveFD", fd)
	}
}

func TestAddingAnFDTwicePanics(t *testing.T) {
	const fd = 1<<20 + 1
	if err := AddFD(fd, nil); err != nil {
		t.Fatalf("AddFD: %v", err)
	}
	t.Cleanup(func() { RemoveFD(fd) })
	defer func() {
		if recover() == nil {
			t.Error("a second AddFD of the same descriptor did not panic")
		}
	}()
	_ = AddFD(fd, nil)
}
