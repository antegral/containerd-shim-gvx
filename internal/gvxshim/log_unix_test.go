//go:build linux || darwin

package gvxshim

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUnixLogUsesContainerdFIFO(t *testing.T) {
	paths := platformFixture(t)
	fifoPath := filepath.Join(paths.Identity.Bundle, "log")
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := os.OpenFile(fifoPath, os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	diagnostics, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := diagnostics.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := openLog(t.Context(), paths, ref, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close(t.Context())
	const message = "containerd log record\n"
	if _, err := output.Writer.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len(message))
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != message {
		t.Fatalf("FIFO record: %q", data)
	}
	if err := output.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fifoPath); err != nil {
		t.Fatalf("containerd FIFO removed: %v", err)
	}
}

func TestUnixLogWithoutReaderWritesDiagnostics(t *testing.T) {
	paths := platformFixture(t)
	fifoPath := filepath.Join(paths.Identity.Bundle, "log")
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		t.Fatal(err)
	}
	file, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fifoPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := platformInfoIdentity(info)
	if err != nil {
		t.Fatal(err)
	}
	sink := &unixLogSink{paths: paths, diagnostics: file, fifoID: &id, timeout: time.Second}
	defer sink.Close()
	if _, err := sink.Write([]byte("fallback")); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := paths.State.Root.ReadFile(ref.Name)
	if err != nil || string(data) != "fallback" {
		t.Fatalf("diagnostics: %q, %v", data, err)
	}
}
