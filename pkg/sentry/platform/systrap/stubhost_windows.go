// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package systrap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Sentry cannot start a process after hostlockdown.Apply, because the
// lockdown job allows one process. A stub host starts before the lockdown. It
// is a second copy of the Sentry executable that runs only the loop in this
// file. It creates one confined stub process per request and duplicates the
// process and thread handles into the Sentry. The stub processes are not
// members of the job of the Sentry.
//
// The host trusts the Sentry and nothing else. A request names no path and no
// command line, so a compromised Sentry cannot start a program of its choice.

const (
	// hostEnv carries the Sentry process ID to the host. Its presence makes the
	// init function of this package run the host loop instead of main.
	hostEnv = "GVX_SYSTRAP_STUBHOST"

	hostMagic   = 0x31485347 // "GSH1"
	opNewStub   = 1
	opSetDebug  = 2
	opRelease   = 3
	hostReqSize = 16
	// hostProtocolVersion is the version of the pipe protocol.
	hostProtocolVersion = 1
	hostRspSize         = 48
)

// confinement names how much of the stub confinement the host applied.
type confinement uint32

const (
	// confineToken is a Low-integrity token without privileges, in a job that
	// allows one process and kills the stub on close.
	confineToken confinement = 1 << iota
	// confineWin32k removes the Win32k system call table of the stub.
	confineWin32k
	// confineStrict adds strict handle checks and disables extension points.
	confineStrict
)

// stubHandles is the host reply for one stub.
type stubHandles struct {
	pid, tid uint32
	proc     windows.Handle
	thread   windows.Handle
	level    confinement
}

func init() {
	if v, ok := os.LookupEnv(hostEnv); ok {
		pid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			os.Exit(2)
		}
		os.Exit(runStubHost(uint32(pid), os.Stdin, os.Stdout))
	}
}

// ---- host side -------------------------------------------------------------

type stubHostLoop struct {
	sentry windows.Handle
	token  windows.Token
	level  confinement
	exe    string
	jobs   map[uint32]windows.Handle
	// debug is the debug object of the Sentry, in the handle table of the host.
	debug windows.Handle
}

// runStubHost serves requests until the Sentry closes the pipe. It returns the
// process exit code.
func runStubHost(sentryPID uint32, in io.Reader, out io.Writer) int {
	h := &stubHostLoop{jobs: make(map[uint32]windows.Handle)}
	sentry, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, sentryPID)
	if err != nil {
		return 3
	}
	h.sentry = sentry
	h.exe, err = os.Executable()
	if err != nil {
		return 4
	}
	h.token, h.level, err = buildStubToken()
	if err != nil {
		return 5
	}
	// The first reply tells the Sentry that the host is ready.
	if err := writeHostReply(out, 0, nil, h.level); err != nil {
		return 6
	}
	for {
		var req [hostReqSize]byte
		if _, err := io.ReadFull(in, req[:]); err != nil {
			// EOF means that the Sentry is gone. Closing the job handles kills the stubs.
			for pid := range h.jobs {
				h.release(pid)
			}
			return 0
		}
		if binary.LittleEndian.Uint32(req[0:]) != hostMagic {
			return 7
		}
		switch binary.LittleEndian.Uint32(req[4:]) {
		case opSetDebug:
			h.debug = windows.Handle(binary.LittleEndian.Uint64(req[8:]))
			if err := writeHostReply(out, 0, nil, h.level); err != nil {
				return 6
			}
			continue
		case opRelease:
			h.release(uint32(binary.LittleEndian.Uint64(req[8:])))
			if err := writeHostReply(out, 0, nil, h.level); err != nil {
				return 6
			}
			continue
		case opNewStub:
		default:
			return 7
		}
		sh, err := h.newStub()
		var errno uint32
		if err != nil {
			errno = uint32(windows.ERROR_GEN_FAILURE)
			var e windows.Errno
			if errors.As(err, &e) {
				errno = uint32(e)
			}
		}
		if err := writeHostReply(out, errno, sh, h.level); err != nil {
			return 6
		}
	}
}

func writeHostReply(out io.Writer, errno uint32, sh *stubHandles, level confinement) error {
	var rsp [hostRspSize]byte
	binary.LittleEndian.PutUint32(rsp[0:], hostMagic)
	binary.LittleEndian.PutUint32(rsp[4:], errno)
	if sh != nil {
		level = sh.level
		binary.LittleEndian.PutUint32(rsp[8:], sh.pid)
		binary.LittleEndian.PutUint32(rsp[12:], sh.tid)
		binary.LittleEndian.PutUint64(rsp[16:], uint64(sh.proc))
		binary.LittleEndian.PutUint64(rsp[24:], uint64(sh.thread))
	}
	binary.LittleEndian.PutUint32(rsp[32:], uint32(level))
	_, err := out.Write(rsp[:])
	return err
}

var (
	modAdvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = modAdvapi32.NewProc("CreateRestrictedToken")
	procCreateProcessAsUserW  = modAdvapi32.NewProc("CreateProcessAsUserW")

	procInitializeProcThreadAttributeList = modKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = modKernel32.NewProc("UpdateProcThreadAttribute")
)

const (
	disableMaxPrivilege = 0x1
	lowIntegritySID     = "S-1-16-4096"

	procThreadAttributeMitigationPolicy = 0x00020007
	mitigationWin32kSystemCallDisable   = uint64(1) << 28
	mitigationStrictHandleChecks        = uint64(1) << 24
	mitigationExtensionPointDisable     = uint64(1) << 32
)

// buildStubToken returns the primary token of every stub: the token of the
// host without privileges, at Low integrity.
//
// WHY: a Low-integrity token cannot write to Medium objects or open most
// processes. Dropping privileges removes SeDebugPrivilege and similar rights.
// The stub needs no handle at all, so the token is the only identity that a
// guest escape would inherit.
func buildStubToken() (windows.Token, confinement, error) {
	var self windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID, &self)
	if err != nil {
		return 0, 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer self.Close()
	var restricted windows.Token
	r, _, e := procCreateRestrictedToken.Call(uintptr(self), disableMaxPrivilege, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if r == 0 {
		return 0, 0, fmt.Errorf("CreateRestrictedToken: %w", e)
	}
	sid, err := windows.StringToSid(lowIntegritySID)
	if err != nil {
		restricted.Close()
		return 0, 0, err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: sid, Attributes: windows.SE_GROUP_INTEGRITY}}
	err = windows.SetTokenInformation(restricted, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)),
		uint32(unsafe.Sizeof(label))+windows.GetLengthSid(sid))
	if err != nil {
		restricted.Close()
		return 0, 0, fmt.Errorf("SetTokenInformation(TokenIntegrityLevel): %w", err)
	}
	return restricted, confineToken, nil
}

// release closes the job of a stub that the Sentry destroyed.
func (h *stubHostLoop) release(pid uint32) {
	if job, ok := h.jobs[pid]; ok {
		_ = windows.CloseHandle(job)
		delete(h.jobs, pid)
	}
}

// newStub creates one confined, suspended stub process and returns handles in
// the Sentry process.
func (h *stubHostLoop) newStub() (*stubHandles, error) {
	cmd, err := windows.UTF16PtrFromString(`"` + h.exe + `" stub`)
	if err != nil {
		return nil, err
	}
	pi, level, err := h.createProcess(cmd)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	job, err := createStubJob()
	if err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, err
	}
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.CloseHandle(job)
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	h.jobs[pi.ProcessId] = job
	h.setPriorities(pi.Process)

	// The host attaches the stub to the debug object of the Sentry. The Sentry
	// then needs no right to debug a process, which a lockdown can remove.
	if h.debug == 0 {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, errors.New("the Sentry sent no debug object")
	}
	if err := ntDebugActiveProcess(pi.Process, h.debug); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, err
	}

	var proc, thread windows.Handle
	self := windows.CurrentProcess()
	if err := windows.DuplicateHandle(self, pi.Process, h.sentry, &proc, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, fmt.Errorf("DuplicateHandle(process): %w", err)
	}
	if err := windows.DuplicateHandle(self, pi.Thread, h.sentry, &thread, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, fmt.Errorf("DuplicateHandle(thread): %w", err)
	}
	return &stubHandles{pid: pi.ProcessId, tid: pi.ThreadId, proc: proc, thread: thread, level: level}, nil
}

// setPriorities gives the stub the I/O and page priority of a normal process.
// A token of Low integrity makes the stub a background process, and the page
// faults of its views then wait behind the I/O of every normal process.
func (h *stubHostLoop) setPriorities(proc windows.Handle) {
	io, ioErr := ntProcessUint32(proc, processIoPriority)
	page, pageErr := ntProcessUint32(proc, processPagePriority)
	if traceEvents {
		tracef("stub host: I/O priority %d (%v), page priority %d (%v)", io, ioErr, page, pageErr)
	}
	if err := ntSetProcessUint32(proc, processIoPriority, ioPriorityNormal); err != nil && traceEvents {
		tracef("stub host: set the I/O priority: %v", err)
	}
	if err := ntSetProcessUint32(proc, processPagePriority, pagePriorityNormal); err != nil && traceEvents {
		tracef("stub host: set the page priority: %v", err)
	}
}

// createProcess starts the suspended stub with the strongest mitigation set
// that the host accepts.
func (h *stubHostLoop) createProcess(cmd *uint16) (*windows.ProcessInformation, confinement, error) {
	policies := []struct {
		bits  uint64
		level confinement
	}{
		{mitigationWin32kSystemCallDisable | mitigationStrictHandleChecks | mitigationExtensionPointDisable, confineToken | confineWin32k | confineStrict},
		{mitigationWin32kSystemCallDisable, confineToken | confineWin32k},
		{0, confineToken},
	}
	var lastErr error
	for _, p := range policies {
		pi, err := h.createWithPolicy(cmd, p.bits)
		if err == nil {
			return pi, p.level, nil
		}
		if traceEvents {
			tracef("stub host: policy %#x failed: %v", p.bits, err)
		}
		lastErr = err
	}
	return nil, 0, lastErr
}

func (h *stubHostLoop) createWithPolicy(cmd *uint16, policy uint64) (*windows.ProcessInformation, error) {
	type startupInfoEx struct {
		windows.StartupInfo
		attrs uintptr
	}
	var si startupInfoEx
	si.Cb = uint32(unsafe.Sizeof(si))
	flags := uintptr(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW)
	var list []byte
	if policy != 0 {
		var size uintptr
		_, _, _ = procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
		list = make([]byte, size)
		if r, _, e := procInitializeProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&list[0])), 1, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
			return nil, fmt.Errorf("InitializeProcThreadAttributeList: %w", e)
		}
		if r, _, e := procUpdateProcThreadAttribute.Call(uintptr(unsafe.Pointer(&list[0])), 0, procThreadAttributeMitigationPolicy,
			uintptr(unsafe.Pointer(&policy)), 8, 0, 0); r == 0 {
			return nil, fmt.Errorf("UpdateProcThreadAttribute(mitigation policy): %w", e)
		}
		si.attrs = uintptr(unsafe.Pointer(&list[0]))
		flags |= windows.EXTENDED_STARTUPINFO_PRESENT
	}
	var pi windows.ProcessInformation
	r, _, e := procCreateProcessAsUserW.Call(uintptr(h.token), 0, uintptr(unsafe.Pointer(cmd)), 0, 0, 0, flags, 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return nil, fmt.Errorf("CreateProcessAsUser: %w", e)
	}
	return &pi, nil
}

// createStubJob returns a job that allows one process, kills it when the host
// closes the last handle, and blocks every window and clipboard operation.
func createStubJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}
	ext := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	ext.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	ext.BasicLimitInformation.ActiveProcessLimit = 1
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&ext)), uint32(unsafe.Sizeof(ext))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject(limits): %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: 0xFF}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject(UI restrictions): %w", err)
	}
	return job, nil
}

// ---- Sentry side -----------------------------------------------------------

// stubHost is the Sentry end of the host pipe.
type stubHost struct {
	mu  sync.Mutex
	cmd *exec.Cmd
	in  io.WriteCloser
	out io.ReadCloser
	// level is the confinement that the host reported for its last stub.
	level confinement
}

// spawnStubHost starts the host process, waits until it is ready, and gives it
// a handle to the debug object.
func spawnStubHost(debug windows.Handle) (*stubHost, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find the Sentry executable: %w", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), hostEnv+"="+strconv.Itoa(os.Getpid()))
	if traceEvents {
		cmd.Stderr = os.Stderr
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the stub host: %w", err)
	}
	h := &stubHost{cmd: cmd, in: in, out: out}
	var rsp [hostRspSize]byte
	if _, err := io.ReadFull(out, rsp[:]); err != nil {
		_ = h.close()
		return nil, fmt.Errorf("the stub host did not report ready: %w", err)
	}
	if binary.LittleEndian.Uint32(rsp[0:]) != hostMagic || binary.LittleEndian.Uint32(rsp[4:]) != 0 {
		_ = h.close()
		return nil, errors.New("the stub host sent a malformed ready message")
	}
	h.level = confinement(binary.LittleEndian.Uint32(rsp[32:]))

	// Duplicate the debug object into the host.
	hostProc, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = h.close()
		return nil, fmt.Errorf("open the stub host: %w", err)
	}
	defer windows.CloseHandle(hostProc)
	var dup windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), debug, hostProc, &dup, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		_ = h.close()
		return nil, fmt.Errorf("give the debug object to the stub host: %w", err)
	}
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[0:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opSetDebug)
	binary.LittleEndian.PutUint64(req[8:], uint64(dup))
	if _, err := in.Write(req[:]); err != nil {
		_ = h.close()
		return nil, fmt.Errorf("send the debug object to the stub host: %w", err)
	}
	if _, err := io.ReadFull(out, rsp[:]); err != nil {
		_ = h.close()
		return nil, fmt.Errorf("the stub host did not accept the debug object: %w", err)
	}
	return h, nil
}

// newStub asks the host for one suspended stub process.
func (h *stubHost) newStub() (*stubHandles, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[0:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opNewStub)
	if _, err := h.in.Write(req[:]); err != nil {
		return nil, fmt.Errorf("send to the stub host: %w", err)
	}
	var rsp [hostRspSize]byte
	if _, err := io.ReadFull(h.out, rsp[:]); err != nil {
		return nil, fmt.Errorf("read from the stub host: %w", err)
	}
	if binary.LittleEndian.Uint32(rsp[0:]) != hostMagic {
		return nil, errors.New("the stub host sent a malformed reply")
	}
	if errno := binary.LittleEndian.Uint32(rsp[4:]); errno != 0 {
		return nil, fmt.Errorf("the stub host could not create a stub: %w", windows.Errno(errno))
	}
	sh := &stubHandles{
		pid:    binary.LittleEndian.Uint32(rsp[8:]),
		tid:    binary.LittleEndian.Uint32(rsp[12:]),
		proc:   windows.Handle(binary.LittleEndian.Uint64(rsp[16:])),
		thread: windows.Handle(binary.LittleEndian.Uint64(rsp[24:])),
		level:  confinement(binary.LittleEndian.Uint32(rsp[32:])),
	}
	h.level = sh.level
	return sh, nil
}

// release tells the host that the stub with the given process ID is gone.
func (h *stubHost) release(pid uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[0:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opRelease)
	binary.LittleEndian.PutUint64(req[8:], uint64(pid))
	if _, err := h.in.Write(req[:]); err != nil {
		return
	}
	var rsp [hostRspSize]byte
	_, _ = io.ReadFull(h.out, rsp[:])
}

// close stops the host. The host exits when the pipe closes, and the kernel
// kills every stub that is still alive.
func (h *stubHost) close() error {
	_ = h.in.Close()
	err := h.cmd.Wait()
	_ = h.out.Close()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return nil
	}
	return err
}
