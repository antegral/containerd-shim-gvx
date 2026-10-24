# ERRATA-002: Post-Refactor Code Review Findings: Memory Safety, Stage-2 Deduplication, and Case-Verified Pinning

This errata specification records four defects discovered during the post-implementation review of commits `3b23cfb` through `f9789ba` ([`GVXIP-003`](../gvxip/gvxip-003-backend-perf-and-compat.md) and [`ERRATA-001`](errata-001-upstream-reuse-and-efficiency.md)). It covers an out-of-bounds host memory read in `platform/hvf`, a timing-dependent test failure under `-race` in `platform/hvf`, duplicate Stage-2 EPT mappings for `pgalloc.MemoryFile` in `platform/whpx`, and unverified directory case during lazy pin reopening in `fsimpl/hostfs`. Implementation agents must execute all four remediation procedures in priority order.

| Field | Value |
| :--- | :--- |
| **Document ID** | `ERRATA-002` |
| **Title** | Post-Refactor Code Review Findings: Memory Safety, Stage-2 Deduplication, and Case-Verified Pinning |
| **Status** | Active Errata and Remediation Work Order |
| **Commit Range Reviewed** | `3b23cfb..f9789ba` |
| **Target Packages** | `pkg/sentry/platform/hvf`, `pkg/sentry/platform/whpx`, `pkg/sentry/fsimpl/hostfs` |
| **Companion Specs** | [`errata-001-upstream-reuse-and-efficiency.md`](errata-001-upstream-reuse-and-efficiency.md), [`../gvxip/gvxip-003-backend-perf-and-compat.md`](../gvxip/gvxip-003-backend-perf-and-compat.md) |

---

## 1. Errata Matrix and Priority Classification (Reference Module)

The table below lists all four review findings, their severity, the affected source files, and the required acceptance gate.

| Errata ID | Priority | Target File and Symbol | Defect Summary | Remediation Gate |
| :--- | :---: | :--- | :--- | :--- |
| **ERRATA-002-E1** | **P0 (Blocking)** | `pkg/sentry/platform/hvf/regions.go` (`regionMap.copyLocked`) | `copyLocked` backs up the `block` pointer to `r.host` and slices `r.size` bytes, reading outside `block` and copying adjacent Sentry memory into the guest VM. | `copyLocked` copies only `block` into `mem[off:off+len(block)]`; zero out-of-bounds `unsafe.Add` calls remain. |
| **ERRATA-002-E2** | **P1 (Important)** | `pkg/sentry/platform/hvf/lifecycle_darwin_test.go` (`TestReplacementStopsVCPUsBeforeTheOldMemoryChanges`) | Fixed `time.Sleep(300 * time.Microsecond)` fails under `-race` when the cancelled vCPU worker takes longer than `300 us` to re-enter guest execution. | Deterministic polling loop verifies `observer[0] != poison` and waits for `next+1` without `time.Sleep`. |
| **ERRATA-002-E3** | **P1 (Important)** | `pkg/sentry/platform/whpx/address_space.go` (`AddressSpace.MapFile`) | Read-only mappings of `pgalloc.MemoryFile` register a read-only Stage-2 arena first and a second writable Stage-2 arena on subsequent writes. | `MapFile` resolves `chunkedFile` (`*pgalloc.MemoryFile`) with `write = true` in Stage-2 while Stage-1 enforces `at.Write`. |
| **ERRATA-002-E4** | **P1 (Important)** | `pkg/sentry/fsimpl/hostfs/dirpin.go` (`Workspace.acquirePinLocked`) | On case-insensitive Unix volumes (macOS APFS), `acquirePinLocked` opens parent directories via `openDirAt` without checking exact filename case. | `acquirePinLocked` verifies exact component case when `!w.host.caseVerified()` before caching `w.pins[rel]`. |

---

## 2. E1: Out-of-Bounds Slice Construction and Host Memory Leak in `pkg/sentry/platform/hvf/regions.go`

When `hv_vm_map` rejects a read-only host buffer (`errHostBlockRejected`), `regionMap.addLocked` falls back to `regionMap.copyLocked` (`pkg/sentry/platform/hvf/regions.go:354-369`) to allocate an anonymous 16KB-aligned private copy (`mem`).

### 2.1 Root Cause Analysis (Descriptive Module)

1. **Out-of-Bounds Pointer Arithmetic in `copyLocked` (`regions.go:361-363`)**:
   - On `darwin/arm64`, `m.granule` is `16384` (`16 KiB`). When `block` is a 4KB slice (`len(block) == 4096`) or starts at a 4KB-aligned address `first` that is not 16KB-aligned, `m.roundOut` sets `r.host = first &^ 0x3fff` (`r.host <= first`) and `r.size = 16384` (`r.size > uintptr(len(block))`).
   - Lines 361 through 363 execute:
     ```go
     first := uintptr(unsafe.Pointer(unsafe.SliceData(block)))
     src := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(block)), int(r.host)-int(first))), r.size)
     copy(mem, src)
     ```
2. **Security and Memory-Safety Consequences**:
   - **Host Memory Leak into Guest Stage-2**: `copy(mem, src)` copies up to `12 KiB` of Sentry heap memory before `block[0]` and after `block[len(block)-1]` into `mem`, which `m.be.mapHost` then maps into guest physical memory (`r.ipa`).
   - **Go `checkptr` Violation Under `-race`**: When `block` is backed by a Go heap allocation smaller than `r.size` or starting at `first > r.host`, `unsafe.Add` with a negative offset and `unsafe.Slice` beyond `cap(block)` violate Go's `checkptr` invariants and abort under `-race`.

### 2.2 Remediation Procedure for E1 (Procedural Module)

> [!CAUTION]
> Never construct an `unsafe.Slice` that extends before `&block[0]` or past `&block[len(block)-1]`. `m.be.allocCopy(r.size)` already returns zero-filled anonymous pages from `mmap`.

1. Open `pkg/sentry/platform/hvf/regions.go` and inspect `copyLocked` at lines 354 through 369.
2. Compute `off := uintptr(unsafe.Pointer(unsafe.SliceData(block))) - r.host`.
3. Replace the `unsafe.Slice` construction with `copy(mem[off:off+uintptr(len(block))], block)`.
4. Add a `-race` unit test in `pkg/sentry/platform/hvf/regions_test.go` for a non-16KB-aligned 4KB slice.
5. Verify that surrounding bytes in `r.copied` remain zero when `resolve` runs with `write = false`.

---

## 3. E2: Flaky `time.Sleep` Synchronization in `pkg/sentry/platform/hvf/lifecycle_darwin_test.go`

Running `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/platform/hvf/...` fails intermittently in `TestReplacementStopsVCPUsBeforeTheOldMemoryChanges` (`lifecycle_darwin_test.go:232`) with `the observer holds 0x1, want 2`.

### 3.1 Root Cause Analysis (Descriptive Module)

1. **Pre-Cancel Value vs. Poison Value (`lifecycle_darwin_test.go:226-235`)**:
   - The guest loop executes `LDR X1, [X0]; STR X1, [X2]; B .-8`, copying the 64-bit word at `guestDataAddr` (`pages[0] == 1` or `pages[1] == 2`) into `observer[0]`.
   - After `mapHostBytes` switches `guestDataAddr` from `cur` (`0`) to `next` (`1`), the test writes `poison` (`0xdead`) into `pages[cur]`, calls `time.Sleep(300 * time.Microsecond)`, and asserts `observer[0] == uint64(next+1)` (`2`).
   - When the test fails, `observer[0]` holds `0x1` (the old valid value from before `mapHostBytes`), never `0xdead` (`poison`).
2. **Worker Re-Entry Latency Under `-race`**:
   - `as.settle()` (`w.quiesce`) returns as soon as the cancelled worker exits `hv_vcpu_run` and stores `w.inGuest.Store(false)` (`vcpu_darwin_arm64.go:246`).
   - Before the worker executes the guest loop again, it must complete `onCancel` (`captureGuest`, reading 31 GPRs and 32 SIMD registers via `hv_vcpu_get_reg`) and `prepareEntry`. If `w.cancel()` stopped the guest between `LDR X1, [X0]` and `STR X1, [X2]`, the first instruction after resume writes the pre-cancel register value `X1` (`1`) once before the next iteration loads `2`.
   - Under `-race`, worker re-entry frequently exceeds `300 us`.

### 3.2 Remediation Procedure for E2 (Procedural Module)

1. Open `pkg/sentry/platform/hvf/lifecycle_darwin_test.go` and inspect `TestReplacementStopsVCPUsBeforeTheOldMemoryChanges` at lines 224 through 236.
2. Remove `time.Sleep(300 * time.Microsecond)`.
3. Poll `atomic.LoadUint64((*uint64)(unsafe.Pointer(&observer[0])))` with a two-second deadline until it equals `uint64(next+1)`.
4. Fail the test immediately if any poll read returns `poison` (`0xdead`).
5. Poll `observer[0]` for `256` additional iterations and assert that it never equals `poison`.
6. Run `go test -race -count=5 -exec "$PWD/scripts/codesign-exec.sh" -run TestReplacementStopsVCPUsBeforeTheOldMemoryChanges ./pkg/sentry/platform/hvf/...`.

---

## 4. E3: Duplicate Read-Only and Read-Write Stage-2 Arenas for `pgalloc.MemoryFile` in `pkg/sentry/platform/whpx`

In `pkg/sentry/platform/whpx/address_space.go` and `gpa.go`, mapping a `pgalloc.MemoryFile` range as read-only (`at.Write == false`) followed by a writable mapping (`at.Write == true`) registers the same host memory twice in two separate Stage-2 GPA arenas.

### 4.1 Root Cause Analysis (Descriptive Module)

1. **Asymmetry Between `hvf` and `whpx` (`hvf/regions.go:307` vs. `whpx/address_space.go:132,142`)**:
   - In `platform/hvf`, `registerChunksLocked` (`hvf/regions.go:307`) recognizes `chunkedFile` (`*pgalloc.MemoryFile`) and maps its backing chunks into Stage-2 with `write = true` (`hvMemoryRead | hvMemoryWrite | hvMemoryExec`), relying on Stage-1 PTEs (`AP` bits) to enforce read-only guest permissions.
   - In `platform/whpx`, `AddressSpace.MapFile` (`whpx/address_space.go:132,142`) passes `at.Write` directly to `f.MapInternal` and `as.p.mem.resolve(bs.Head().ToSlice(), at.Write, runs)`.
2. **Duplicate `WHvMapGpaRange` Calls on CoW and Recycled Pages**:
   - `pgalloc.MemoryFile` backing views are always allocated with `PAGE_READWRITE` on the host.
   - When a guest maps a `MemoryFile` range with `PROT_READ` (such as a fork CoW page or read-only anonymous page), `resolveWindow` (`whpx/gpa.go:280`) allocates a read-only Stage-2 arena (`arenaKey{index, writable: false}`) and calls `WHvMapGpaRange`.
   - When the guest later writes to that page (CoW break, `mprotect`, or `MemoryFile` frame reuse), `resolveWindow` allocates a second writable Stage-2 arena (`arenaKey{index, writable: true}`) and calls `WHvMapGpaRange` a second time for the same host page.

### 4.2 Remediation Procedure for E3 (Procedural Module)

1. Open `pkg/sentry/platform/whpx/address_space.go` and define `type chunkedFile interface { TotalSize() uint64 }`.
2. Compute `hostWrite := at.Write || isChunkedFile(f)` inside `AddressSpace.MapFile` (`whpx/address_space.go:132-147`).
3. Pass `hostWrite` to `f.MapInternal` and `as.p.mem.resolve(bs.Head().ToSlice(), hostWrite, runs)`.
4. Keep `as.install(addr, runs, at)` unchanged so Stage-1 PTEs enforce read-only guest permissions.
5. Add a unit test in `pkg/sentry/platform/whpx/persistent_map_test.go` for read-then-write `chunkedFile` mappings.
6. Verify in that test that `mapGPA` runs only once for the shared backing chunk.

---

## 5. E4: Missing Case-Sensitivity Verification in `Workspace.acquirePinLocked` (`pkg/sentry/fsimpl/hostfs/dirpin.go`)

On case-insensitive Unix filesystems (the default macOS APFS volume format), `Workspace.acquirePinLocked` (`pkg/sentry/fsimpl/hostfs/dirpin.go:75-107`) can reopen and pin a parent directory descriptor using a mismatched case string.

### 5.1 Root Cause Analysis (Descriptive Module)

1. **Difference Between Windows and Unix `openDirAt` (`inode_windows.go:255` vs. `inode_unix.go:185`)**:
   - On Windows, `hostRoot.openDirAt` (`inode_windows.go:255`) calls `verifyLeaf(h, name)`, so `hostRoot.caseVerified()` is `true` and `openDirAt` rejects wrong-case directory names.
   - On Unix (`inode_unix.go:185`), `hostRoot.openDirAt` calls `openatRetry(int(dir), name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, 0)`, which succeeds on case-insensitive APFS even when `name` differs in case from the on-disk directory entry.
2. **Unchecked Pin Re-Acquisition Path (`dirpin.go:88-106`)**:
   - While `lookupIn` (`dirpin.go:286`) checks `w.exactNameIn(rel, pin)` for the leaf component, `acquirePinLocked` (`dirpin.go:88-106`) opens `parentRel` and `name` via `w.host.openDirAt(parent.h, name)` without calling `exactNameIn`.
   - If a directory pin was evicted (`maxDirPins` or `pinIdleTime`) or if `lookupPath("DIR/child")` is called directly when `"dir"` exists on disk, `acquirePinLocked("DIR")` opens `"dir"` and caches it under `w.pins["DIR"]`.

### 5.2 Remediation Procedure for E4 (Procedural Module)

1. Open `pkg/sentry/fsimpl/hostfs/dirpin.go` and inspect `acquirePinLocked` at lines 75 through 107.
2. Verify exact component case when `!w.host.caseVerified()` before caching a pin in `acquirePinLocked`.
3. Close `h` and return `nameMismatch(rel)` if the on-disk directory name does not match `name`.
4. Add a unit test in `pkg/sentry/fsimpl/hostfs/dirpin_unix_test.go` for wrong-case parent directory lookups.
5. Verify that `lookupPath("SUB/file")` and post-eviction pin reopening return `fs.ErrNotExist` when `"sub"` exists.

---

## 6. Verification and Audit Procedure (Procedural Module)

> [!IMPORTANT]
> Run `go test` through `scripts/codesign-exec.sh` on macOS. Confirm that the `1.0%` upstream diff budget (`-max-ratio=0.01`) and all six cross-compilation targets pass.

1. Run the native `-race` test suites for `hvf`, `whpx`, `hostfs`, and `tools/upstream` on `darwin/arm64`.
2. Cross-compile all packages across `darwin/arm64`, `darwin/amd64`, `windows/amd64`, `windows/arm64`, `linux/amd64`, and `linux/arm64`.
3. Run the upstream diff audit tool with `-max-ratio=0.01`.
4. Run the ASD-STE100 punctuation and lexicon checks against `docs/errata/`.

```bash
# 1. Run native unit tests with -race on darwin/arm64
go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/platform/hvf/... ./pkg/sentry/platform/whpx/... ./pkg/sentry/fsimpl/hostfs/... ./tools/upstream/...

# 2. Cross-compile all six target platforms
GOOS=darwin  GOARCH=arm64 go build ./...
GOOS=darwin  GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=arm64 go build ./...
GOOS=linux   GOARCH=amd64 go build ./...
GOOS=linux   GOARCH=arm64 go build ./...

# 3. Verify upstream diff budget (< 1.0%)
go run ./tools/upstream -mode=audit -offline -max-ratio=0.01

# 4. Verify zero em-dashes, spaced en-dashes, or prose arrows in documentation
rg -n "\x{2014}| \x{2013} |\x{2192}" README.md AGENTS.md docs/ 2>/dev/null
```
