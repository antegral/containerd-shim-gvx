//go:build darwin || windows

package fd

import (
	"os"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T, name string) *HostHandle {
	t.Helper()
	h, err := OpenHostPath(filepath.Join(t.TempDir(), name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("OpenHostPath: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func TestHostHandleReadWriteAndClose(t *testing.T) {
	t.Parallel()
	h := openTemp(t, "handle.bin")

	payload := []byte("gvx-host-handle")
	if n, err := h.WriteAt(payload, 0); err != nil || n != len(payload) {
		t.Fatalf("WriteAt = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	buf := make([]byte, len(payload))
	if n, err := h.ReadAt(buf, 0); err != nil || n != len(payload) {
		t.Fatalf("ReadAt = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	if string(buf) != string(payload) {
		t.Fatalf("ReadAt = %q, want %q", buf, payload)
	}

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
	if _, err := h.RawHandle(); err == nil {
		t.Fatal("RawHandle after Close succeeded, want error")
	}
	if _, err := h.ReadAt(buf, 0); err == nil {
		t.Fatal("ReadAt after Close succeeded, want error")
	}
}

// TestHostHandleReadAtEndOfFile verifies pread(2) semantics: a read at or past
// the end returns a short count and no error on every host.
func TestHostHandleReadAtEndOfFile(t *testing.T) {
	t.Parallel()
	h := openTemp(t, "eof.bin")
	if _, err := h.WriteAt([]byte("abcd"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	buf := make([]byte, 8)
	if n, err := h.ReadAt(buf, 2); err != nil || n != 2 || string(buf[:n]) != "cd" {
		t.Fatalf("ReadAt across end = (%d, %v, %q), want (2, nil, cd)", n, err, buf[:n])
	}
	if n, err := h.ReadAt(buf, 4); err != nil || n != 0 {
		t.Fatalf("ReadAt at end = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := h.ReadAt(buf, 1<<20); err != nil || n != 0 {
		t.Fatalf("ReadAt past end = (%d, %v), want (0, nil)", n, err)
	}
}

func TestHostHandleDupSharesFileAndCloseIsIndependent(t *testing.T) {
	t.Parallel()
	h := openTemp(t, "dup.bin")
	dup, err := h.Dup()
	if err != nil {
		t.Fatalf("Dup: %v", err)
	}
	defer dup.Close()
	if _, err := h.WriteAt([]byte("x"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close original: %v", err)
	}
	buf := make([]byte, 1)
	if n, err := dup.ReadAt(buf, 0); err != nil || n != 1 || buf[0] != 'x' {
		t.Fatalf("duplicate ReadAt after closing original = (%d, %v, %q), want (1, nil, x)", n, err, buf)
	}
}

func TestHostHandleReleaseTransfersOwnership(t *testing.T) {
	t.Parallel()
	h := openTemp(t, "release.bin")
	raw, err := h.Release()
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := h.Release(); err == nil {
		t.Fatal("second Release succeeded, want error")
	}
	if _, err := h.RawHandle(); err == nil {
		t.Fatal("RawHandle after Release succeeded, want error")
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close after Release = %v, want nil: the caller owns the descriptor", err)
	}
	// The released descriptor stays open for the caller.
	owned, err := NewHostHandle(handleArg(raw))
	if err != nil {
		t.Fatalf("NewHostHandle(released): %v", err)
	}
	if _, err := owned.WriteAt([]byte("ok"), 0); err != nil {
		t.Fatalf("WriteAt through released descriptor: %v", err)
	}
	if err := owned.Close(); err != nil {
		t.Fatalf("Close released descriptor: %v", err)
	}
}

func TestOpenHostPathReportsMissingFile(t *testing.T) {
	t.Parallel()
	if h, err := OpenHostPath(filepath.Join(t.TempDir(), "absent"), os.O_RDONLY, 0); err == nil {
		_ = h.Close()
		t.Fatal("OpenHostPath(missing) succeeded, want error")
	}
}
