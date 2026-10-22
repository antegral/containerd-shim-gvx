# Windows `systrap` Engine: Measured Behavior and Design

This document records what the project measured on Windows hosts for a `winsystrap` engine. It also records the design that those measurements allow. The engine runs a Linux guest natively inside a stub process, without a hypervisor. Read [`architecture.md`](architecture.md) section 3.3 first for the shared `systrap` concepts.

| Topic | Result |
| :--- | :--- |
| Status | Not implemented. `systrap_windows.go` returns `*ErrUnavailable`. |
| `windows/arm64` with `arm64` guests | Feasible. All blocking questions have a measured answer. |
| `windows/amd64` with `amd64` guests | Feasible for correctness. Windows has no kernel filter that proves syscall completeness. |
| Strongest result | A debugger process can receive guest faults and rewrite registers. It needs no code in the stub. |
| Largest open risk | `ntdll` code stays executable in the stub, so a hostile guest can still reach NT system calls. |

## 1. Purpose and Scope

The `whpx` backend is the primary Windows engine. It needs the Windows Hypervisor Platform (WHP). Some hosts have no WHP. The `windows-11-arm` hosted runner reports `WHvCapabilityCodeHypervisorPresent = 0`. Parallels states that Apple silicon hosts do not support nested virtualization (KB 116239, reviewed October 2024). Windows on ARM virtual machines there therefore probably lack WHP.

A Windows `systrap` engine would let those hosts run guests. It would also let CI run real guests on `windows-11-arm`. The `windows-latest` runner has WHP (`present = 1`), so the `amd64` engine has less value than the `arm64` engine.

This document covers the engine design and the evidence for it. It does not change any code. The SPEC keeps `winsystrap` marked as not implemented until a milestone in section 10 passes.

## 2. Measurement Method

The probes are Go programs in [`windows-systrap-probes/`](windows-systrap-probes/). They use only the `syscall` package and raw machine code that the probe generates at run time. They need no C toolchain.

Each probe ran on a throwaway orphan branch. A workflow with `on: push` built the probe and ran it on two GitHub-hosted runners. `windows-latest` is `amd64`. `windows-11-arm` is `arm64`. The runs are listed in section 11.

All results come from one image per architecture. Another Windows build can differ. Repeat the probes on the target build before you rely on a number. The procedure is in section 12.

## 3. Verified Findings

Every row below is a measurement unless the row says "documented". Times are averages. Run identifiers appear in section 11.

### 3.1 Memory

The engine needs 4KB mappings of a shared memory file in the address space of another process. The SPEC assumed 64KB regions. The probes show that placeholders remove that limit.

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| `VirtualAlloc2` placeholder in a remote process, split into 4KB placeholders | works | works |
| `MapViewOfFile3` with `MEM_REPLACE_PLACEHOLDER` at a non-64KB address and offset | works | works |
| Two remote addresses map the same 4KB section page | both read the same bytes | both read the same bytes |
| Protection change on one 4KB view after a `PAGE_EXECUTE_READWRITE` mapping | RX, R, NOACCESS, RWX all work | same |
| Protection change to execute after a `PAGE_READWRITE` mapping | fails with `ERROR_INVALID_PARAMETER` | fails |
| Placeholders at `0x10000`, `0x400000`, 1TB, and 16TB in a fresh remote process | all succeed | all succeed |
| Remote 4KB split, map, protect, unmap | 4.0, 2.6, 2.0, 2.9 µs | 1.7, 1.4, 1.8, 7.2 µs |

Rule: map every guest view as `PAGE_EXECUTE_READWRITE`, then lower the protection with `VirtualProtectEx`. A view that starts as read-write can never become executable.

The exports `VirtualAlloc2`, `MapViewOfFile3`, and `WaitOnAddress` live in `kernelbase.dll`. They are not exports of `kernel32.dll` on either runner. `pkg/memutil/memutil_windows.go` looks up `MapViewOfFile3` in `kernel32.dll`, so that path always falls back to `MapViewOfFile`. The fallback works for mappings in the current process. The tree keeps this behavior until a change replaces it.

### 3.2 Cross-Process Signaling

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| `WaitOnAddress` woken by `WakeByAddressSingle` from another process over shared memory | no wake in 4000 ms | no wake in 4000 ms |
| Round trip of two auto-reset events between two processes | 19.5 to 27.4 µs | 12.0 to 12.6 µs |
| `CreateProcess(CREATE_SUSPENDED)`, terminate, wait | 1.2 to 2.6 ms | 2.7 to 3.0 ms |

`WaitOnAddress` keeps its wait list in the memory of one process, so it cannot signal across processes. Microsoft documents that the waker is a thread of the same process. The stub and the Sentry must signal with event objects. The SPEC text that names `WakeByAddressSingle` for this link is wrong.

### 3.3 System Call Behavior

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| Service number location | `EAX` | immediate of `svc` (`NtClose` is `svc #0xF`) |
| `syscall` or `svc` executed from private RWX memory | runs as an NT service | runs as an NT service |
| Linux numbers 0 to 3 with zero arguments | NT services 0 to 3 run and return `NTSTATUS` | same |
| `SetProcessMitigationPolicy(ProcessSystemCallFilterPolicy)` with `FilterId = 1` | fails with `ERROR_INVALID_PARAMETER` | fails |
| `SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy)` with `0x1` and `0x5` | succeeds | succeeds |
| Same policy with `0x4` alone | `ERROR_ACCESS_DENIED` | `ERROR_ACCESS_DENIED` |

Windows traps no system call instruction. An unpatched Linux `syscall` or `svc` runs as the NT service with the same number. The call returns an `NTSTATUS` in the register where the guest expects a Linux result. Windows offers no per-process filter to an unprivileged process. The `0x5` policy value blocks Win32k and file-system control calls. It does not block other services.

### 3.4 CPU State

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| `RDFSBASE` and `WRFSBASE` in user mode | execute | not applicable |
| FS base after a sleep, a yield, or 300 ms of contention | reset to 0 | not applicable |
| `TPIDR_EL0` with a junk value across 200 real 5 ms kernel waits | not applicable | kept |
| `x18` with a junk value across 200 real 5 ms kernel waits | not applicable | kept |
| `mrs x0, ctr_el0` | not applicable | `STATUS_ILLEGAL_INSTRUCTION` |
| `ic ivau` | not applicable | `STATUS_ILLEGAL_INSTRUCTION` |
| `dc cvau`, `dc zva`, `mrs x0, dczid_el0` | not applicable | execute |

Windows resets the FS base of a thread when it switches contexts. A Linux `amd64` guest keeps its thread pointer there. A recovery method in section 7.2 restored the value 908 times in 1.5 seconds with no wrong read. On `arm64`, Windows uses `x18` for the TEB and treats `TPIDR_EL0` as reserved. Neither register changed across real waits.

### 3.5 Debugger Path

A debugger process can receive a guest fault before Windows runs any user-mode dispatch code in the stub. This is the Windows analog of `ptrace` for faults.

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| First-chance exception reaches the debugger with the faulting address | yes | yes |
| `GetThreadContext` and `SetThreadContext` change registers and resume | yes | yes (`x0` came back as written) |
| Guest `x18` holds a junk value during the exception | not applicable | the process survived and resumed |
| Time per event (wait, read context, write context, continue) | 89.9 µs for `int3` | 61.2 to 74.7 µs |
| `ud2` or `brk #imm` event on a trap instruction | `int3` event arrives, `ud2` untested | `brk #imm` event arrives as an illegal instruction |
| `mrs ctr_el0` event emulated by the debugger | not applicable | works, 74.7 µs |

Caution for `amd64`: the `CONTEXT` structure starts with six home slots, so `ContextFlags` sits at offset 48. A wrong offset returns an all-zero context and no error.

### 3.6 Stub Process and `ntdll`

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| `NtCreateThreadEx` with `SKIP_LOADER_INIT` and `SKIP_THREAD_ATTACH` runs guest-like code in a running process | yes | yes |
| Same call after `ntdll` `.text` becomes read-only | the thread did not run and the process died | same |
| Same call after every syscall instruction in `ntdll` `.text` becomes an undefined instruction (524 and 1444 sites) | the thread did not run and the process died | same |
| A generated minimal PE image with no imports | starts, then exits with `0xC000007B` | same |

A new thread starts in `ntdll!RtlUserThreadStart`. That path needs executable `ntdll` code and its syscall instructions. Removing `ntdll` syscall gadgets therefore breaks thread creation. The design in section 6.5 works around this. The minimal PE attempt is unfinished. It does not show that a generated PE is impossible.

### 3.7 Instruction Scan of Real Binaries

The scan in [`windows-systrap-probes/x86scan/`](windows-systrap-probes/x86scan/) read the Alpine 3.20.10 root filesystems. It covered 17 `x86-64` ELF files and 17 `aarch64` ELF files.

| Measure | `x86-64` | `aarch64` |
| :--- | :--- | :--- |
| Executable bytes scanned | 4.42 MB | 3.81 MB |
| Syscall pattern in executable bytes | 539 pairs of `0F 05` (121.8 per MB) | 478 words of `svc` |
| Real syscall instructions by linear decode | 505 | 478 |
| Pattern inside another instruction | 34 (6.3% of the pairs) | 0 |
| Labels that changed between 16 sweep start offsets | 0 | not applicable |
| Pattern in non-executable data | 54 pairs (27.6 per MB) | 1 word (0.43 per MB) |

A blind byte replacement of `0F 05` would corrupt 34 instructions in 4.42 MB of `x86-64` code. On `aarch64`, every aligned word is an instruction, and the pattern is a 32-bit value. The decode was stable on this compiler output. The sample is small and it holds no JIT code.

## 4. The Nirvana Hook Is a Recovery Net, Not a Security Layer

The SPEC lists `ProcessInstrumentationCallback` (information class 40) as the "Unpatched Syscall Safety Net". The kernel calls the callback when it returns to user mode. By then the kernel has already run the NT service. The callback sees the return address in `R10` and can detect a `0F 05` at `R10 - 2`.

This design has three consequences. First, the hook cannot stop the first NT service from running with Linux arguments. Second, a hostile guest can probably remove the hook with a hidden `syscall` that calls `NtSetInformationProcess`. This part is inference and no probe tested it. Third, installing the hook on the current process needs no privilege, so the stub can install it at start (ntdoc, `ProcessInstrumentationCallback`).

Use the hook for one job: detect that a site was missed, patch the site, and replay the Linux call. Treat each detection as a defect in the patcher. Do not count the hook in the security model.

## 5. Why Variable-Length Instructions Matter

The `x86-64` `syscall` instruction is two bytes. A same-size replacement fits every site. The bytes `0F 0B` (`ud2`) or `CC 90` (`int3` plus `nop`) trap and keep every other byte in place. The debugger path resolves the trap. Patching is therefore possible on `amd64`.

The 5-byte `jmp rel32` fast path in the SPEC is harder. It overwrites three bytes after the `syscall`. The patcher must move those instructions into a trampoline, fix any `RIP`-relative operand, and prove that no branch lands inside the window. That work needs exact instruction boundaries. The SPEC patterns A, B, and C exist for this reason.

Finding the sites is the main problem. A byte scan has false positives: 34 of 539 pairs were not syscalls. A decoder that starts at a known boundary removes them. The decoder gives no guarantee for four kinds of code:

- Data that sits inside executable sections, such as tables and padding.
- Hand-written assembly with computed jumps.
- Just-in-time compiled code with no symbols.
- Code that a guest writes after the scan.

An indirect jump into the middle of an instruction can run a hidden `0F 05`. A hostile guest plants such a jump on purpose. Linux uses `seccomp` to catch every such call. macOS uses a Seatbelt filter that kills the stub. Windows has no equivalent. The engine can therefore make benign guests correct, but it cannot prove completeness for hostile `amd64` code.

`arm64` is different. Every instruction is four bytes and aligned. A scan of every aligned word in executable pages finds every `svc` that can run. The page-trap design keeps pages non-executable until the Sentry scans them, so no `svc` can run in a guest page without a scan. This holds for guest pages only. Section 8 explains the gap that remains.

## 6. Design for `windows/arm64`

The engine reuses the macOS design where Windows allows it. The macOS code in `pkg/sentry/platform/systrap` supplies the patcher (`patcher_arm64_xplat.go`, already tagged `darwin || windows`), the code image logic, and the Sentry-side address space model.

### 6.1 Components

| Component | Role |
| :--- | :--- |
| Stub host (helper process) | Starts before `hostlockdown.Apply`. Creates stub processes, jobs, and debug objects on request. Passes handles to the Sentry with `DuplicateHandle`. |
| Stub process | Runs guest code. Holds no handle except one event pair per thread. Runs under a restricted Low-integrity token and its own job. |
| Sentry | Owns the memory file, the guest address space map, and the patcher. Receives faults through a debug object. |
| `sysmsg` page | Shared memory with one block per guest thread. Holds the spilled registers and the virtual register values. |
| Debug object | One native debug object receives the faults of many stub processes. |

### 6.2 Address Space

The Sentry creates a placeholder for the guest range in each stub process. It splits placeholders to 4KB and maps memory file pages with `MapViewOfFile3(MEM_REPLACE_PLACEHOLDER)`. Every view starts as `PAGE_EXECUTE_READWRITE`. The Sentry then sets the protection that the guest mapping needs.

Execute permission stays off until the page trap runs. Endpoint protection software can flag executable views that start as writable. Section 9 lists this risk.

### 6.3 Page Trap and Patching

1. Map a guest page with the guest protection minus execute.
2. Receive the execute fault through the debug object.
3. Copy the page into a private section and scan every aligned word.
4. Replace each `svc #0` with a branch to a trampoline slot.
5. Replace every other `svc` with an undefined instruction.
6. Replace `mrs ctr_el0` with a constant load, and emulate `ic ivau` as a no-op or a flush call.
7. Map the patched copy as execute-read and call `FlushInstructionCache`.

Step 5 turns a hostile `svc #N` into a fault that the debugger sees. Step 6 follows the macOS patcher. The patcher on macOS already rewrites `mrs ctr_el0`. The `ic ivau` case is new, because macOS allows it.

### 6.4 Fast Path and Slow Path

A patched `svc #0` branches to a trampoline slot. The slot spills the guest registers to the `sysmsg` block. It signals the Sentry event and waits on its own event with one `NtSignalAndWaitForSingleObject` call. The measured event round trip is 12.0 to 12.6 µs.

All other guest events use the debug object. These are page faults, illegal instructions, and breakpoints. The measured cost is 61 to 75 µs per event. The Sentry reads and writes the full thread context. `x18` does not matter on this path, because Windows never runs user-mode dispatch code for a first-chance exception that a debugger continues.

The trampoline must restore the host `x18` value before it calls into `ntdll`. It must restore the guest value before it returns to guest code. The stub keeps the `sysmsg` pointer in `TPIDR_EL0`, because the patcher already rewrites every guest access to that register.

### 6.5 Threads and `ntdll`

A guest `clone` with `CLONE_THREAD` needs a new stub thread. The probes show that a loader-less thread runs code only while `ntdll` stays intact. The design therefore keeps `ntdll` executable and accepts this exposure. A later milestone can pre-create a pool of parked threads and then remove the `ntdll` gadgets. That change limits each guest address space to the pool size.

### 6.6 Stub Image

The stub needs a process with no Go runtime. Three options exist. The project can commit a prebuilt stub as it does on macOS. It can generate a PE image in Go. It can start an existing system executable that waits.

The first option has the lowest risk. The second needs a working minimal PE, which section 3.6 shows as unfinished.

## 7. Design for `windows/amd64`

The `amd64` engine follows section 6 for memory, signaling, the stub host, and the debugger path. This section lists only the differences.

### 7.1 Syscall Patching

The patcher decodes each executable page with `x86asm` from symbol, `.eh_frame`, or entry boundaries. It replaces each decoded `syscall` with a same-size trap (`0F 0B`). It replaces the SPEC patterns A and B only when a decode proves the window safe. It leaves a `0F 05` pair that sits inside another instruction untouched. It treats just-in-time code pages as pages with no syscall. The callback of section 4 detects a missed site.

### 7.2 FS Base Recovery

A Linux guest keeps its thread pointer in the FS base. Windows resets the base to zero on a context switch. A read such as `mov %fs:0x28, %rax` then faults at address `0x28`, and a read such as `mov %fs:-0x10, %eax` faults in kernel space. The debugger receives each fault. It stores the guest `RAX` and `RIP` in the stub, redirects `RIP` to a trampoline, and continues. The trampoline runs `WRFSBASE` with the saved guest value, restores `RAX`, and jumps back to the faulting instruction.

The measured recovery handled 908 faults in 1.5 seconds with a sleep every 20 reads. No read returned a wrong value. The method has two known gaps. A guest that executes `RDFSBASE` reads zero after a switch, so the patcher must rewrite that instruction. A guest that uses `%fs:(%reg)` with a register that holds a mapped address does not fault.

### 7.3 Red Zone

The System V ABI gives a leaf function 128 bytes below `RSP`. A user-mode exception dispatch writes a `CONTEXT` structure below `RSP` and destroys that zone. The debugger path avoids that write, because the kernel resumes the thread without user-mode dispatch. The engine must never let an exception reach user-mode dispatch.

## 8. Security Model

| Engine | Syscall filter | Guest can reach host NT services | Basis |
| :--- | :--- | :--- | :--- |
| Linux `systrap` | `seccomp` allowlist in the Sentry, trap for guests | no | kernel filter |
| macOS `systrap` | Seatbelt profile kills the stub | no | kernel filter |
| Windows `whpx` and `hvf` | none needed | no | hardware virtualization |
| Windows `arm64` `winsystrap` | none | yes, through `ntdll` stubs | token, job, mitigation policy, page scan |
| Windows `amd64` `winsystrap` | none | yes, through `ntdll` stubs and hidden `0F 05` | token, job, mitigation policy |

The Windows `arm64` engine blocks every `svc` in guest pages before it runs. A hostile guest can still jump to an `svc` inside `ntdll` and choose the registers. That call runs with the token of the stub. The stub token is a Low-integrity restricted token.

The stub job blocks new processes. The mitigation policy `0x5` blocks Win32k and file-system control calls. The stub holds no handle except its event pair, so most NT services fail with `STATUS_INVALID_HANDLE`. This resembles the exposure of a sandboxed browser renderer. That comparison is inference.

State this limit in every user-facing document for the engine. Do not describe the engine as a syscall sandbox on Windows. A Windows host that needs that guarantee must use `whpx`.

## 9. Unverified Assumptions

Each item below needs a probe or a prototype before the engine ships.

| Priority | Assumption | How to test |
| :--- | :--- | :--- |
| 1 | A helper that started before the lockdown can create stubs, and the locked Sentry can use their handles. | Lock a test process with `hostlockdown.Apply`. Ask the helper for a stub. Map memory into it. |
| 2 | One debug object serves many stub processes and many threads without a serialization bottleneck. | Run 8 stub processes with 4 threads each. Measure events per second. |
| 3 | A stub process starts without the Go runtime from a prebuilt or generated image. | Build a stub with an LLVM toolchain. Run it on both runners. |
| 4 | Patching `ic ivau` as a no-op keeps JIT guests (V8, JVM) correct. | Run `node` and a JVM with the patch. |
| 5 | The debugger path scales for guests that fault on many pages. | Touch 100 MB in a guest and measure the time. |
| 6 | Endpoint protection software tolerates the stub host and the debug object. | Run on a host with Microsoft Defender at default settings. |
| 7 | The `NtSignalAndWaitForSingleObject` round trip matches the measured event round trip. | Measure with two processes. |

## 10. Implementation Milestones

| Milestone | Deliverable | Verified by |
| :--- | :--- | :--- |
| W1 | Native debug object wrappers, stub host, job and token confinement | Unit tests on both runners. |
| W2 | Stub address space with 4KB placeholders and per-page protection | Unit tests on both runners. |
| W3 | `arm64` code image scan, patcher reuse, trampoline generator, fast and slow path | A static guest prints a line on `windows-11-arm`. |
| W4 | `arm64` thread, signal, and fork support | The e2e `systrap` suite on `windows-11-arm`. |
| W5 | `amd64` patcher, FS base recovery, trampoline generator | A static guest prints a line on `windows-latest`. |
| W6 | `amd64` thread, signal, and fork support | The e2e `systrap` suite on `windows-latest`. |
| W7 | Hardening: callback, mitigation policies, soak tests, documentation | CI and the weekly image gates. |

## 11. Evidence

| Run | Runners | Content |
| :--- | :--- | :--- |
| `39790745508` | both | Exports, stub bytes, direct syscalls, mitigation policy, spawn time. |
| `39791228959` | both | Placeholders, executable views, remote 4KB cost, FS base loss, event round trip. |
| `39791535847` | both | `arm64` `x18`, `TPIDR_EL0`, `ctr_el0`, `ic ivau`, WHP presence. |
| `39796084304` | both | Debugger event latency and register writes. |
| `39800771242`, `39802593217`, `39803097982` | both | `x18` across waits, policy flags, `ntdll` patching, loader-less threads. |
| `39803487649` | both | FS base recovery with the debugger. |

The scan of section 3.7 ran on a development host. Its output is in [`windows-systrap-probes/x86scan/RESULTS.txt`](windows-systrap-probes/x86scan/RESULTS.txt).

## 12. Reproduction Procedure

> [!CAUTION]
> Run the probes only from a throwaway branch. They execute raw machine code and raw NT system calls. Delete the branch after the run.

1. Create an orphan branch with the probe directory and a workflow.
2. Set the workflow trigger to `push` on that branch.
3. Use the runner labels `windows-latest` and `windows-11-arm`.
4. Run `go build` in the probe directory with Go 1.24 or newer.
5. Run the resulting executable and read lines that start with `PROBE`, `DBG`, or `R2`.
6. Delete the branch and keep the logs.

## 13. Sources

| Source | Supports |
| :--- | :--- |
| [Pico Process Overview](https://learn.microsoft.com/en-us/archive/blogs/wsl/pico-process-overview) | No third-party API for pico processes. |
| [MapViewOfFile3](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3) | The 64KB limit does not apply with `MEM_REPLACE_PLACEHOLDER`. |
| [WaitOnAddress](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress) | The waker is a thread of the same process. |
| [Windows ARM64 ABI](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions?view=msvc-170) | `x18` is the TEB. `TPIDR_EL0` is reserved. |
| [ProcessInfoClass notes (ntdoc)](https://raw.githubusercontent.com/m417z/ntdoc/main/descriptions/processinfoclass.md) | The instrumentation callback needs no privilege for the current process. |
| [Parallels KB 116239](https://kb.parallels.com/en/116239) | Nested virtualization is unsupported on Apple silicon. |
| [ASC-Hook](https://arxiv.org/abs/2412.05784) | Prior work on `svc` rewriting on `arm64`. |
| [gVisor `systrap` README](https://github.com/google/gvisor/blob/master/pkg/sentry/platform/systrap/README.md) | Linux uses `seccomp` traps for syscalls. |
