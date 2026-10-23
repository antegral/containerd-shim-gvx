package gvxshim

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsEndpointUsesProtectedLocalPipe(t *testing.T) {
	paths := platformFixture(t)
	endpoint, err := listenLocal(t.Context(), paths, taskEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Listener.Close()
	if endpoint.Ref.Socket != nil {
		t.Fatal("Windows endpoint has filesystem socket ownership")
	}
	if duplicate, err := listenLocal(t.Context(), paths, taskEndpoint); err == nil {
		duplicate.Listener.Close()
		t.Fatal("existing pipe bind accepted")
	}
	accepted := make(chan net.Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		conn, err := endpoint.Listener.Accept()
		if err != nil {
			acceptError <- err
			return
		}
		accepted <- conn
	}()
	client, err := dialLocal(t.Context(), paths.TaskAddress)
	if err != nil {
		endpoint.Listener.Close()
		<-acceptError
		t.Fatal(err)
	}
	defer client.Close()
	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptError:
		t.Fatal(err)
	}
	defer server.Close()
	handle, ok := server.(interface{ Fd() uintptr })
	if !ok {
		t.Fatal("pipe connection does not expose its native handle")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("pipe DACL is not protected: %#x, %v", control, err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("missing pipe DACL: %v", err)
	}
	type aclHeader struct {
		Revision  byte
		Reserved  byte
		Size      uint16
		Count     uint16
		Reserved2 uint16
	}
	count := (*aclHeader)(unsafe.Pointer(acl)).Count
	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{owner: false, "S-1-5-18": false}
	if int(count) != len(expected) {
		t.Fatalf("pipe DACL ACE count: %d, want %d", count, len(expected))
	}
	for index := range uint32(count) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		seen, ok := expected[sid]
		if !ok || seen || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("unexpected pipe ACE: SID=%q, type=%d", sid, ace.Header.AceType)
		}
		expected[sid] = true
	}
	server.SetDeadline(time.Now().Add(5 * time.Second))
	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte{7}); err != nil {
		t.Fatal(err)
	}
	var payload [1]byte
	if _, err := server.Read(payload[:]); err != nil || payload[0] != 7 {
		t.Fatalf("pipe payload: %v, %v", payload, err)
	}
}

func TestWindowsLocalDialRejectsRemotePipes(t *testing.T) {
	for _, address := range []string{`\\remote\pipe\gvx`, `npipe:////remote/pipe/gvx`, "tcp://127.0.0.1:1"} {
		if conn, err := dialLocal(t.Context(), address); err == nil {
			conn.Close()
			t.Errorf("accepted %q", address)
		} else if !errors.Is(err, errUnsafeEntry) {
			t.Errorf("remote pipe error: %v", err)
		}
	}
}

func TestWindowsUnsafeStateACLIsNotRepaired(t *testing.T) {
	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := canonicalBundle(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(bundle, ".gvx-shim")
	name, err := windows.UTF16PtrFromString(statePath)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		t.Fatal(err)
	}
	handle, err := platformOpenInitial(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	before, err := windows.GetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	id := instanceIdentity{Owner: owner, Namespace: "unsafe-acl", ID: "instance", Bundle: bundle, ContainerdAddress: `\\.\pipe\platform-containerd`}
	if paths, err := openPaths(t.Context(), id, createPaths); err == nil {
		paths.Close()
		t.Fatal("world-writable state accepted")
	}
	after, err := windows.GetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("unsafe ACL changed: before %s, after %s", before, after)
	}
	entries, err := os.ReadDir(statePath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unsafe directory modified: %v, %v", entries, err)
	}
}
