# ERRATA-001: Upstream gVisor Smartdiff Audit, Redundant Reimplementations, and Backend Inefficiencies

This errata specification records the semantic diff (`smartdiff`) between `gvx` and pinned upstream gVisor (`UPSTREAM_COMMIT` `0d2072ab24130458e928ea0a78b363a60705e433`), excluding module-path rewrites and build-constraint lines. It documents seven architectural defects where `gvx` either reimplemented existing upstream gVisor components or introduced avoidable hot-path inefficiencies across Tier 1 and Tier 2 packages. Implementation agents must execute the remediation procedures in this document in priority order.

| Field | Value |
| :--- | :--- |
| **Document ID** | `ERRATA-001` |
| **Title** | Upstream gVisor Smartdiff Audit, Redundant Reimplementations, and Backend Inefficiencies |
| **Status** | Active Errata and Remediation Work Order |
| **Upstream Baseline** | `0d2072ab24130458e928ea0a78b363a60705e433` (`upstream/go`) |
| **Isolation Tiers** | Tier 1 (`platform/whpx`, `platform/hvf`, `fsimpl/hostfs`), Tier 2 (`platform/systrap`, `pkg/fdnotifier`), Tier 3 (`tools/upstream/buildtag_allowlist.txt`) |
| **Companion Specs** | [`../gvxip/gvxip-003-backend-perf-and-compat.md`](../gvxip/gvxip-003-backend-perf-and-compat.md), [`../architecture.md`](../architecture.md) |

---

## 1. Upstream Smartdiff Audit Summary (Descriptive Module)

The upstream baseline contains `2,485` Go and assembly source files. After stripping `gvisor.dev/gvisor` to `z.gfire.dev/gvx` import rewrites and `//go:build` tag changes, only `11` hand-written upstream files contain logic modifications (`+262 / -32` lines). The table below summarizes the repository footprint across all three isolation tiers.

| Category | File Count | Non-Test Lines | Architectural Disposition |
| :--- | ---: | ---: | :--- |
| **Pristine Upstream Files** | `1,802` | - | Zero logic differences after module-path normalization. |
| **Fenced Upstream Files (`linux-only`)** | `604` | - | Restricted to Linux via `tools/upstream/buildtag_allowlist.txt`. |
| **Expanded Upstream Files (`expand`)** | `4` | - | Enabled on `darwin` and `windows` in `pkg/ring0` and `pkg/sentry/fsimpl/erofs`. |
| **Generated Format-Only Files** | `64` | - | Whitespace formatting differences in `*_autogen.go` and `*.pb.go`. |
| **Modified Upstream Source Files** | `11` | `+262 / -32` | Targeted seam patches in `erofs`, `arch`, `loader`, `mm`, `syserr`, `sighandling`, and `platforms`. |
| **Added Files in Tier 3 Packages** | `13` | `1,136` | Additive helpers for `xattr`, `addrhole`, `exec_image`, `futex`, and `linux_errno`. |
| **Tier 2 Sibling Files (`_darwin`, `_windows`, `_xplat`)** | `126` | `14,619` | `pkg/sentry/platform/systrap` (`11,571` lines) and host OS primitive wrappers. |
| **Tier 1 Additive Packages** | `311` | `39,070` | `whpx` (`4,769` lines), `hvf` (`4,539` lines), `hostfs` (`7,030` lines), `oci` (`6,845` lines). |

### 1.1 Modified Upstream Source Files (Reference Module)

Every logic modification in shared upstream files belongs to one of six functional seams. The table below lists each modified upstream file and its exact purpose.

| Upstream File | Changed Lines | Purpose of Modification |
| :--- | ---: | :--- |
| `pkg/erofs/erofs.go`, `pkg/erofs/erofs_state_autogen.go`, `pkg/sentry/fsimpl/erofs/erofs.go`, `pkg/sentry/fsimpl/erofs/filesystem.go` | `+173 / -9` | Parse inline and shared extended attributes (`security.capability`) and expose device `rdev` numbers. |
| `pkg/sentry/arch/arch_aarch64.go` | `+2 / -1` | Preserve `s.Regs.TPIDR_EL0` in `Context64.PtraceSetRegs` instead of zeroing the TLS pointer. |
| `pkg/sentry/loader/elf.go` | `+66 / -0` | Union segment permissions via `mergeSharedPagePerms` when 4KB-aligned `PT_LOAD` segments share a 16KB host page. |
| `pkg/sentry/mm/vma.go` | `+5 / -0` | Call `excludePlatformAddressHoles` in `createVMALocked` to reserve `systrap` arena holes. |
| `pkg/syserr/syserr.go`, `pkg/syserr/host_darwin.go` | `+11 / -8` | Translate `linuxerr.Error` by Linux errno number via `fromLinuxError` instead of casting to host `unix.Errno`. |
| `pkg/sighandling/sighandling_darwin.go`, `pkg/sentry/platform/platforms/platforms_darwin.go` | `+5 / -14` | Replace upstream Darwin error stubs with no-op signal forwarding and register `platform/hvf`. |

---

## 2. Errata Matrix: Redundant Reimplementations and Inefficiencies (Reference Module)

While keeping Tier 3 changes below `0.5%`, earlier milestones fenced out several OS-agnostic upstream packages and reimplemented their mechanics with higher overhead in Tier 1 and Tier 2. The table below ranks all seven errata items by runtime impact and maintenance cost.

| Errata ID | Priority | Target Packages | Upstream Reference | Defect Summary | Remediation Gate |
| :--- | :---: | :--- | :--- | :--- | :--- |
| **ERRATA-001-E1** | **P0** | `platform/systrap` (`darwin`), `platform/whpx`, `platform/hvf` | `platform/systrap/systrap.go:372`, `platform/kvm/kvm.go:145` | `MapUnit()` returns `4 KiB` or `16 KiB` instead of `0` or `2 MiB+`, multiplying page faults by `64x` to `512x`. | Non-exec PMA faults map full or multi-MB ranges in one `MapFile` call. |
| **ERRATA-001-E2** | **P0** | `platform/whpx`, `platform/hvf` | `platform/kvm/address_space.go`, `platform/kvm/physical_map.go` | `MapFile` and `Unmap` invoke `WHvMapGpaRange` / `hv_vm_map` and mutate Go `map` entries per 4KB page. | Stage-2 GPA mappings persist per `MemoryFile` chunk; `MapFile`/`Unmap` touch only Stage-1 page tables. |
| **ERRATA-001-E3** | **P1** | `platform/hvf`, `platform/whpx` | `pkg/ring0/pagetables`, `pkg/ring0` | `hvf` reimplements a 730-line page-table walker (`pagetable.go`); `whpx` and `hvf` duplicate 2,000 lines of Ring-0/EL1 stubs. | `hvf` uses `pkg/ring0/pagetables`; `whpx` and `hvf` share one guest-stub package. |
| **ERRATA-001-E4** | **P1** | `platform/whpx`, `platform/hvf` | `platform/kvm/kvm.go:140`, `pkg/sentry/mm/io.go:136` | `SupportsAddressSpaceIO()` returns `true`, forcing lock acquisition, per-page map lookups, and Stage-2 faults on `CopyIn`/`CopyOut`. | `SupportsAddressSpaceIO()` returns `false`; both backends embed `platform.NoAddressSpaceIO`. |
| **ERRATA-001-E5** | **P2** | `platform/systrap` (`darwin`, `windows`) | `platform/systrap/usertrap`, `platform/systrap/context_queue.go` | `buildtag_allowlist.txt` fences all of `systrap/`, preventing reuse of `usertrap` (`amd64` 5-byte `jmp`) and `context_queue.go`. | `usertrap` (`amd64`) builds on `darwin` and `windows`; `systrap` shares queue primitives. |
| **ERRATA-001-E6** | **P2** | `pkg/sentry/fsimpl/hostfs` | `pkg/sentry/fsutil`, `pkg/sentry/fsimpl/gofer` | `hostfs/regular_file.go` maintains a custom 64KB chunk map and flushes the entire file on every dirty `PRead`. | `PRead` flushes only the overlapping byte range and reuses `fsutil` range tracking. |
| **ERRATA-001-E7** | **P3** | `pkg/fdnotifier` | `pkg/fdnotifier/fdnotifier.go` | `fdnotifier_darwin.go` and `fdnotifier_windows.go` duplicate 90 lines of mutex and `fdMap` boilerplate from `fdnotifier.go`. | `fdnotifier.go` builds on all OS targets; only `poll_*` files remain OS-specific. |
| **ERRATA-001-E8** | **P1** | `tools/upstream`, Tier 2 `_xplat` files, `fsimpl/ext4lite` | `tools/upstream/diff_audit.go:111,142` | 12 additive helper files lack `_xplat`/`_darwin` suffixes (`1.13%` budget); `ext4lite` and `hvcommon` need Tier 1 registration. | `go run ./tools/upstream -mode=audit -max-ratio=0.01` passes (`< 1.0%`). |

---

## 3. E1: `Platform.MapUnit()` Misconfiguration Across `darwinsystrap`, `whpx`, and `hvf`

In upstream gVisor, `MemoryManager.mapASLocked` (`pkg/sentry/mm/address_space.go:64-90`) expands every guest page fault to an alignment boundary returned by `Platform.MapUnit()`. Returning the hardware page size from `MapUnit()` defeats pre-mapping and forces a separate fault trap on every 4KB or 16KB page.

### 3.1 Root Cause Analysis (Descriptive Module)

1. **Upstream `MapUnit()` Contract (`pkg/sentry/mm/address_space.go:64-90`)**:
   - Upstream `Systrap.MapUnit()` (`pkg/sentry/platform/systrap/systrap.go:372-376`) returns `0`, instructing `mapASLocked` to map the entire PMA in a single `AddressSpace.MapFile` call.
   - Upstream `KVM.MapUnit()` (`pkg/sentry/platform/kvm/kvm.go:145-151`) returns `16 << 20` (`16 MiB`) so one VM-exit populates up to 16 MiB of guest page-table entries.
2. **Current Misconfiguration in `gvx`**:
   - `darwinsystrap.MapUnit()` (`pkg/sentry/platform/systrap/platform_darwin.go:203-205`) returns `blockSize` (`16 KiB`), even though `AddressSpace.MapFile` (`address_space_darwin.go:186-246`) already maps arbitrary multi-page ranges in a single `vmRemap` and `vmProtect` pair.
   - `WHPX.MapUnit()` (`pkg/sentry/platform/whpx/whpx.go:279-281`) and `HVF.MapUnit()` (`pkg/sentry/platform/hvf/hvf.go:104-106`) return `pageSize` (`4 KiB`). Faulting in a 4 MiB heap or shared library therefore triggers `1,024` separate VM-exits instead of `1` or `2`.

### 3.2 Remediation Procedure for E1 (Procedural Module)

> [!IMPORTANT]
> Complete E4 (`SupportsAddressSpaceIO() == false`) and verify that `MapFile` in `whpx` and `hvf` coalesces contiguous Stage-2 and Stage-1 updates before raising `MapUnit()` above `2 MiB`.

1. Open `pkg/sentry/platform/whpx/whpx.go` and update `WHPX.MapUnit()` at line 279 to return `2 << 20` (`2 MiB`).
2. Open `pkg/sentry/platform/hvf/hvf.go` and update `HVF.MapUnit()` at line 104 to return `2 << 20` (`2 MiB`).
3. Open `pkg/sentry/platform/systrap/platform_darwin.go` and update `Platform.MapUnit()` at line 203 to return `256 << 10` (`256 KiB`).
4. Run `go test` on `whpx`, `hvf`, and `systrap` to verify that sequential memory touches reduce fault counts.

---

## 4. E2: Per-Page Stage-2 Hypervisor Mapping in `whpx` and `hvf` vs. Upstream `platform/kvm`

Both `platform/whpx` and `platform/hvf` currently couple guest virtual memory operations (`AddressSpace.MapFile` and `AddressSpace.Unmap`) to per-page Stage-2 hypervisor syscalls (`WHvMapGpaRange`, `WHvUnmapGpaRange`, `hv_vm_map`, `hv_vm_unmap`) and per-4KB Go `map` lookups.

### 4.1 Root Cause Analysis (Descriptive Module)

1. **Upstream `platform/kvm` Two-Stage Separation (`pkg/sentry/platform/kvm/address_space.go:114-208`)**:
   - Upstream `kvm` maps whole `pgalloc.MemoryFile` backing chunks into Stage-2 guest physical memory (`KVM_SET_USER_MEMORY_REGION`) once when a chunk is first registered.
   - `addressSpace.MapFile` and `addressSpace.Unmap` never call `KVM_SET_USER_MEMORY_REGION` to unmap 4KB pages; they only update Stage-1 page tables in host memory via `PageTables.Map` and `PageTables.Unmap` across contiguous ranges.
2. **Per-4KB Loop and EPT Shootdown Storm in `platform/whpx` (`whpx/address_space.go:130-247`, `whpx/gpa.go:175-227`)**:
   - `AddressSpace.acquireSlices` (`whpx/address_space.go:130-157`) and `AddressSpace.install` (`whpx/address_space.go:203-221`) split every contiguous `MapInternal` buffer into individual 4KB pages.
   - For each 4KB page, `whpx` calls `gpaMapper.AcquirePage` (`WHvMapGpaRange` for `4096` bytes), calls `as.pt.Map(va, 4096, ...)`, and inserts entries into two Go maps (`as.pages[va]` and `m.pages[hostPageAddr]`).
   - When the guest calls `munmap`, `AddressSpace.Unmap` (`whpx/address_space.go:224-247`) calls `gpaMapper.Release`, which invokes `WHvUnmapGpaRange(4096)` on every unreferenced 4KB page. Each `WHvUnmapGpaRange` call acquires the partition EPT lock in the Windows kernel and broadcasts an EPT TLB shootdown IPI across host cores.
3. **Identical Per-Page Overhead in `platform/hvf` (`hvf/address_space.go:71-180`, `hvf/vm_darwin.go:140-220`)**:
   - `hvf/address_space.go` iterates 4KB page by 4KB page, records every 4KB virtual page in `as.pages map[uint64]pageEntry`, and reference-counts 16KB host pages in `vm_darwin.go` to call `hv_vm_map` and `hv_vm_unmap` on guest `mmap` and `munmap` cycles.

### 4.2 Remediation Procedure for E2 (Procedural Module)

> [!CAUTION]
> Keep Stage-2 GPA mappings for `pgalloc.MemoryFile` backing regions registered for the lifetime of the VM partition (or until the `MemoryFile` chunk itself is unmapped). Never call `WHvUnmapGpaRange` or `hv_vm_unmap` on individual 4KB pages during guest `AddressSpace.Unmap`.

1. Open `pkg/sentry/platform/whpx/gpa.go` and register contiguous `MapInternal` slices in Stage-2 once for the partition lifetime.
2. Remove per-4KB `WHvUnmapGpaRange` calls from `gpaMapper.Release` during guest `AddressSpace.Unmap`.
3. Open `pkg/sentry/platform/whpx/address_space.go` and call `as.pt.Map` once per contiguous `safemem.Block`.
4. Use the `bool` return values of `as.pt.Map` and `as.pt.Unmap` to trigger `as.invalidate()`.
5. Delete `as.pages map[uint64]pageEntry` from `whpx/address_space.go` after E4, while preserving `as.forgetIdleRoots()` in `Release()`.
6. Apply the same contiguous Stage-2 registration and range-based Stage-1 updates to `pkg/sentry/platform/hvf/vm_darwin.go` and `address_space.go`.

---

## 5. E3: Redundant `GuestPageTable` and Ring-0/EL1 Stubs Across `hvf`, `whpx`, and `pkg/ring0`

`gvx` maintains three separate implementations of x86-64/ARM64 page tables and Ring-0/EL1 exception vectors across `pkg/ring0`, `pkg/sentry/platform/whpx`, and `pkg/sentry/platform/hvf`.

### 5.1 Root Cause Analysis (Descriptive Module)

1. **Duplicate Page-Table Implementation in `platform/hvf` (`hvf/pagetable.go`, `pte_arm64.go`, `pte_x86.go`, `pte_amd64.go`)**:
   - Upstream gVisor provides `pkg/ring0/pagetables`, which already builds on `darwin` and `windows` (`amd64` and `arm64`) and powers `platform/whpx`.
   - `platform/hvf` ignores `pkg/ring0/pagetables` and implements a custom 730-line `GuestPageTable` (`hvf/pagetable.go`). Its `mapPageLocked` method (`pagetable.go:145-185`) performs four Go `map[uint64][]byte` hash lookups (`t.pages[next]`) per 4KB page and lacks contiguous-range walking.
2. **Duplicate Hand-Encoded Machine Code Stubs in `whpx` and `hvf`**:
   - `whpx` (`stubgen_x86.go`, `stubgen_a64.go`, `kernel.go`, `segments_x86.go`: `1,066` lines) and `hvf` (`bluepill_x86.go`, `bluepill_arm64.go`, `kernel_x86.go`, `kernel_darwin_arm64.go`, `sysreg_arm64.go`: `989` lines) independently generate x86-64 GDT/IDT/TSS tables, `SYSCALL`/`HLT` handlers, and ARM64 `VBAR_EL1` exception vectors with shared CommPage layouts.

### 5.2 Remediation Procedure for E3 (Procedural Module)

1. Replace `GuestPageTable` in `pkg/sentry/platform/hvf/address_space.go` with `pkg/ring0/pagetables.PageTables`.
2. Delete `pkg/sentry/platform/hvf/pagetable.go`, `pte_arm64.go`, `pte_x86.go`, and `pte_amd64.go` after `hvf` tests pass.
3. Extract the shared CommPage layout and Ring-0/EL1 vector generators from `whpx` and `hvf` into `pkg/sentry/platform/hvcommon`.

---

## 6. E4: Unnecessary `SupportsAddressSpaceIO() == true` in `whpx` and `hvf`

Both `platform/whpx` and `platform/hvf` opt into `AddressSpace` I/O (`SupportsAddressSpaceIO() == true`), which is a legacy hook designed for `ptrace` platforms where the Sentry does not share memory with the guest.

### 6.1 Root Cause Analysis (Descriptive Module)

1. **Upstream `SupportsAddressSpaceIO()` Contract (`pkg/sentry/mm/io.go:136-157`)**:
   - Both upstream `KVM` (`pkg/sentry/platform/kvm/kvm.go:140`) and upstream `Systrap` (`pkg/sentry/platform/systrap/systrap.go:367`) return `false` from `SupportsAddressSpaceIO()` and embed `platform.NoAddressSpaceIO`.
   - When `SupportsAddressSpaceIO()` is `false`, `MemoryManager.CopyOut`, `CopyIn`, and `ZeroOut` copy directly to and from `pgalloc.MemoryFile` internal mappings (`imCopyOut`, `imCopyIn`) without acquiring any `AddressSpace` lock or faulting pages into the hypervisor.
2. **Lock and Fault Penalty in `whpx` and `hvf` (`whpx/address_space.go:322-425`, `hvf/address_space.go:232-343`)**:
   - Because `WHPX.SupportsAddressSpaceIO()` (`whpx.go:274`) and `HVF.SupportsAddressSpaceIO()` (`hvf.go:99`) return `true`, every syscall buffer copy under `32 KiB` calls `AddressSpace.CopyIn` or `CopyOut`.
   - Those methods acquire `as.mu.RLock()`, look up every 4KB page in `as.pages`, and return `platform.SegmentationFault` whenever a buffer page has not yet been faulted into the hypervisor (`mm/io.go:149`), forcing an unnecessary `MapFile` (`WHvMapGpaRange` / `hv_vm_map`) call for memory that only the Sentry kernel touches.

### 6.2 Remediation Procedure for E4 (Procedural Module)

1. Open `pkg/sentry/platform/whpx/whpx.go` and change `WHPX.SupportsAddressSpaceIO()` at line 274 to return `false`.
2. Embed `platform.NoAddressSpaceIO` in `AddressSpace` inside `pkg/sentry/platform/whpx/address_space.go`.
3. Delete `CopyOut`, `CopyIn`, `ZeroOut`, `SwapUint32`, and `sliceForPageLocked` from `pkg/sentry/platform/whpx/address_space.go` (lines 322 through 425).
4. Open `pkg/sentry/platform/hvf/hvf.go` and change `HVF.SupportsAddressSpaceIO()` at line 99 to return `false`.
5. Embed `platform.NoAddressSpaceIO` in `AddressSpace` inside `pkg/sentry/platform/hvf/address_space.go`.
6. Delete `CopyOut`, `CopyIn`, `ZeroOut`, `SwapUint32`, and `hostSliceLocked` from `pkg/sentry/platform/hvf/address_space.go` (lines 232 through 343).
7. Run `go test` on `pkg/sentry/platform/whpx` and `pkg/sentry/platform/hvf`.

---

## 7. E5: Over-Fenced `pkg/sentry/platform/systrap` and `usertrap` Components

Lines 102 through 104 of `tools/upstream/buildtag_allowlist.txt` fence the entire `pkg/sentry/platform/systrap`, `sysmsg`, and `usertrap` directories as `linux-only`.

### 7.1 Root Cause Analysis (Descriptive Module)

1. **OS-Agnostic Upstream `usertrap` (`pkg/sentry/platform/systrap/usertrap/usertrap_amd64_unsafe.go`)**:
   - Upstream `usertrap` implements atomic 5-byte `jmp rel32` binary rewriting for x86-64 `syscall` (`0F 05`) instructions, including `int3` fallback when an adjacent instruction overlaps the 5-byte patch window.
   - Because `usertrap` was fenced as `linux-only`, `winsystrap` (`amd64`) still traps every syscall via kernel debug exceptions (`CC 90`), and `darwinsystrap` (`amd64`) lacks shared access to the upstream x86-64 trampoline rewriter.
2. **OS-Agnostic Context Queue (`pkg/sentry/platform/systrap/context_queue.go`)**:
   - Upstream `context_queue.go` implements the shared-memory ring buffer and adaptive polling heuristics in pure Go + `sync/atomic`, without Linux syscalls.

### 7.2 Remediation Procedure for E5 (Procedural Module)

1. Change `pkg/sentry/platform/systrap/usertrap/` from `linux-only` to `expand` in `tools/upstream/buildtag_allowlist.txt` for pure-Go x86-64 files.
2. Reuse `usertrap.State` in `winsystrap` (`sysmsg` trampoline mode) and `darwinsystrap` on `darwin/amd64`.

---

## 8. E6: Custom Chunk Cache in `pkg/sentry/fsimpl/hostfs` vs. `pkg/sentry/fsutil`

`pkg/sentry/fsimpl/hostfs/regular_file.go` implements a custom 64KB chunk cache (`fileData.chunks map[uint64]*cacheChunk`) instead of reusing upstream `pkg/sentry/fsutil` range sets.

### 8.1 Root Cause Analysis (Descriptive Module)

1. **Whole-File Dirty Flush on Every `PRead` (`pkg/sentry/fsimpl/hostfs/regular_file.go:279-315`)**:
   - In `regularFileFD.PRead` (`regular_file.go:296-300`), whenever `d.hasDirtyChunks()` is `true`, `PRead` calls `d.flushLocked()`, which writes every dirty 64KB chunk across the entire file to the host disk before reading the requested range.
   - `PRead` then allocates a new `io.NewSectionReader` heap object on every call (`regular_file.go:303`) instead of reading directly from cached chunks or calling `h.ReadAt` on the byte range.
2. **Upstream `pkg/sentry/fsutil` Availability**:
   - `pkg/sentry/fsutil` (`FileRangeSet`, `DirtySet`) already compiles on `darwin` and `windows` and tracks dirty page intervals in a gap-tree without scanning a `map[uint64]*cacheChunk`.

### 8.2 Remediation Procedure for E6 (Procedural Module)

1. Open `pkg/sentry/fsimpl/hostfs/regular_file.go` and inspect `PRead` at lines 296 through 305.
2. Flush only dirty chunks overlapping `[offset, offset+size)` instead of calling `d.flushLocked()` across the entire file.
3. Replace `io.NewSectionReader(h, offset, int64(size))` in `PRead` with direct `h.ReadAt` calls to avoid per-call heap allocations.

---

## 9. E7: Duplicated Boilerplate in `pkg/fdnotifier`

`pkg/fdnotifier/fdnotifier_darwin.go` and `pkg/fdnotifier/fdnotifier_windows.go` duplicate the entire OS-independent `notifier` struct and method set from upstream `pkg/fdnotifier/fdnotifier.go`.

### 9.1 Root Cause Analysis (Descriptive Module)

1. **OS-Independent `pkg/fdnotifier/fdnotifier.go`**:
   - Upstream `pkg/fdnotifier/fdnotifier.go` (`144` lines) contains zero Linux imports; all epoll-specific logic lives in `poll_unsafe.go`.
   - Because `tools/upstream/buildtag_allowlist.txt` (line 21) marked `pkg/fdnotifier` as `linux-only`, `fdnotifier_darwin.go` and `fdnotifier_windows.go` each copied the same 90 lines of `notifier` mutex and `fdMap` boilerplate.

### 9.2 Remediation Procedure for E7 (Procedural Module)

1. Update `tools/upstream/buildtag_allowlist.txt` so `pkg/fdnotifier/fdnotifier.go` builds on `linux || darwin || windows`.
2. Keep `pkg/fdnotifier/poll_unsafe.go` restricted to `linux-only`.
3. Delete the duplicated `notifier` struct and methods from `pkg/fdnotifier/fdnotifier_darwin.go` and `pkg/fdnotifier/fdnotifier_windows.go`.

---

## 10. E8: Tighten Upstream Diff Budget to `1.0%` (`-max-ratio=0.01`) and Register Tier 1 `ext4lite`

`tools/upstream` (`diff_audit.go:92-98`) charges `Expand + Seam + Shadow + Added` (`28 / 2485` files = `1.13%`) against the Tier 3 budget because `12` additive cross-platform helper files lack the `_xplat` or `_darwin` filename token required by `isSiblingOSFile` (`diff_audit.go:142`). In addition, `pkg/sentry/fsimpl/ext4lite` ([`../gvxip/gvxip-001-better-posix-hostfs.md`](../gvxip/gvxip-001-better-posix-hostfs.md) and [`../gvxip/gvxip-002-ext4lite-volume-engine.md`](../gvxip/gvxip-002-ext4lite-volume-engine.md)) and `pkg/sentry/platform/hvcommon` (`E3`) belong to Tier 1 (`tier1Prefixes`).

### 10.1 Root Cause Analysis (Descriptive Module)

1. **Misclassified Tier 2 Additive Sibling Files (`tools/upstream/diff_audit.go:140-151`)**:
   - `ClassifyFile` classifies any file in a shared package as Tier 2 (`Tier2Sibling`, `0%` budget impact) when its filename contains an underscore-separated `windows`, `darwin`, or `xplat` token.
   - Because `pkg/erofs/xattr.go`, `pkg/fd/fd_other.go`, `pkg/hostarch/hostarch_arm64_16k.go` (and its `_state_autogen.go`), `pkg/memutil/arena_registry.go`, `pkg/sentry/{kernel,mm,platform}/addrhole.go`, `pkg/sentry/mm/gvx_exec_image.go`, `pkg/sentry/platform/exec_image.go`, `pkg/sync/futex.go`, and `pkg/syserr/linux_errno.go` omit `_xplat` or `_darwin`, `RunAudit` charges all `13` files as Tier 3 `Added`.
   - Renaming those additive sibling files to `*_xplat.go` (and `hostarch_darwin_arm64_16k.go`) lowers the total touched ratio below the `1.0%` (`-max-ratio=0.01`) ceiling (`24/2485 = 0.97%` with `E5` expanded).
2. **Tier 1 Exemption for `ext4lite` and `hvcommon` (`tools/upstream/diff_audit.go:111-124`)**:
   - `pkg/sentry/fsimpl/ext4lite/` (`GVXIP-001` and `GVXIP-002`) and `pkg/sentry/platform/hvcommon/` (`ERRATA-001-E3`) are pure `gvx` additive packages that never exist in `upstream/go`. Registering both prefixes in `tier1Prefixes` and `tools/upstream/boundaries.go` excludes them from the Tier 3 diff ratio.

### 10.2 Remediation Procedure for E8 (Procedural Module)

1. Open `tools/upstream/diff_audit.go` and append `"pkg/sentry/fsimpl/ext4lite/"` and `"pkg/sentry/platform/hvcommon/"` to `tier1Prefixes`.
2. Open `tools/upstream/boundaries.go` and register the allowed import rules for `pkg/sentry/fsimpl/ext4lite` and `pkg/sentry/platform/hvcommon`.
3. Rename the additive sibling files in shared packages (`xattr.go`, `fd_other.go`, `arena_registry.go`, `addrhole.go`, `gvx_exec_image.go`, `exec_image.go`, `futex.go`, `linux_errno.go`) to `*_xplat.go`.
4. Rename `pkg/hostarch/hostarch_arm64_16k.go` and `hostarch_arm64_16k_state_autogen.go` to `hostarch_darwin_arm64_16k.go` and `hostarch_darwin_arm64_16k_state_autogen.go`.
5. Update default `-max-ratio` in `tools/upstream/main.go`, `.github/workflows/ci.yml`, and `AGENTS.md` from `0.05` (`5.0%`) to `0.01` (`1.0%`).
6. Run `go run ./tools/upstream -mode=audit -offline -max-ratio=0.01` and verify that the audit passes.

---

## 11. Verification and Audit Procedure (Procedural Module)

> [!IMPORTANT]
> Run `go test` through `scripts/codesign-exec.sh` on macOS. Always verify the `1.0%` upstream diff budget (`-max-ratio=0.01`) after modifying any `tools/upstream/buildtag_allowlist.txt` rule.

1. Run the native test suite for each modified package on `darwin/arm64`.
2. Cross-compile all packages across `darwin/arm64`, `darwin/amd64`, `windows/amd64`, `windows/arm64`, `linux/amd64`, and `linux/arm64`.
3. Run the upstream diff audit tool to confirm modified upstream files remain below `1.0%` (`-max-ratio=0.01`).
4. Run the ASD-STE100 punctuation and lexicon checks against `docs/errata/`.

```bash
# 1. Test modified packages natively on darwin/arm64
go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/platform/hvf/... ./pkg/sentry/platform/whpx/... ./pkg/sentry/platform/systrap/... ./pkg/sentry/fsimpl/hostfs/... ./pkg/fdnotifier/... ./tools/upstream/...

# 2. Cross-compile all six target platforms
GOOS=darwin  GOARCH=arm64 go build ./...
GOOS=darwin  GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=arm64 go build ./...
GOOS=linux   GOARCH=amd64 go build ./...
GOOS=linux   GOARCH=arm64 go build ./...

# 3. Verify upstream diff budget (< 1.0%, excluding Tier 1 ext4lite and hvcommon)
go run ./tools/upstream -mode=audit -offline -max-ratio=0.01

# 4. Verify zero em-dashes, spaced en-dashes, or prose arrows in documentation
rg -n "\x{2014}| \x{2013} |\x{2192}" README.md AGENTS.md docs/ 2>/dev/null
```
