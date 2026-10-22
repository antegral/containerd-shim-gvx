//go:build windows

package fd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestOpenHostPathHonoursDispositionFlags(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "disposition.bin")
	h, err := OpenHostPath(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("OpenHostPath(O_CREATE|O_EXCL): %v", err)
	}
	if _, err := h.WriteAt([]byte("data"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if again, err := OpenHostPath(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600); err == nil {
		_ = again.Close()
		t.Fatal("O_CREATE|O_EXCL on an existing file succeeded, want error")
	}

	truncated, err := OpenHostPath(path, os.O_TRUNC|os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenHostPath(O_TRUNC): %v", err)
	}
	defer truncated.Close()
	buf := make([]byte, 4)
	if n, err := truncated.ReadAt(buf, 0); err != nil || n != 0 {
		t.Fatalf("ReadAt after O_TRUNC = (%d, %v), want (0, nil)", n, err)
	}
}

func TestOpenHostPathRejectsAppend(t *testing.T) {
	t.Parallel()
	_, err := OpenHostPath(filepath.Join(t.TempDir(), "append.bin"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if !errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		t.Fatalf("OpenHostPath(O_APPEND) err = %v, want ERROR_NOT_SUPPORTED", err)
	}
}
