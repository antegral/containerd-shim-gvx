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

//go:build darwin && arm64

package hvf

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// TestAddressSpaceChurnReusesTablesWithoutLeakOrAliasing is the regression test
// for the stale walk-cache hazard. Every iteration builds a fresh address
// space, which reuses the table pages that the previous one released. The
// guest reads a value that only this iteration wrote. A stale cached walk would
// read the previous iteration's memory or fault. The slab must not grow.
func TestAddressSpaceChurnReusesTablesWithoutLeakOrAliasing(t *testing.T) {
	plat := newTestPlatform(t)
	vm := plat.vm
	ctx := plat.NewContext(context.Background()).(*Context)
	ac := arch.New(arch.Host)

	runOnce := func(i int) {
		asIface, err := plat.NewAddressSpace(platform.AddressSpaceOptions{})
		if err != nil {
			t.Fatalf("iteration %d: NewAddressSpace: %v", i, err)
		}
		as := asIface.(*AddressSpace)
		arena, err := memutil.AllocateAnonymousArena(hostPageSize)
		if err != nil {
			t.Fatalf("iteration %d: arena: %v", i, err)
		}
		binary.LittleEndian.PutUint32(arena[0:], 0xf9400001) // LDR X1, [X0]
		binary.LittleEndian.PutUint32(arena[4:], insnSVC0)
		const marker = 0x5eed_0000
		binary.LittleEndian.PutUint64(arena[pageSize4K:], marker+uint64(i))
		mapHostBytes(t, as, guestCodeAddr, arena[:pageSize4K], hostarch.AccessType{Read: true, Execute: true})
		// A distant data address uses different level-0, level-1 and level-2 tables.
		dataVA := hostarch.Addr(0x7f00_0000_0000) + hostarch.Addr(i%7)*0x4000_0000
		mapHostBytes(t, as, dataVA, arena[pageSize4K:2*pageSize4K], hostarch.ReadWrite)

		ac.SetIP(uintptr(guestCodeAddr))
		ac.SetStack(uintptr(dataVA) + 0x800)
		ac.StateData().Regs.Regs[0] = uint64(dataVA)
		ac.StateData().Regs.Regs[1] = 0
		mm := &stubMemoryManager{as: as}
		sig, _, err := ctx.Switch(context.Background(), mm, ac, 0)
		if sig != nil || err != nil {
			t.Fatalf("iteration %d: Switch = (%v, %v)", i, sig, err)
		}
		if got := ac.StateData().Regs.Regs[1]; got != marker+uint64(i) {
			t.Fatalf("iteration %d: the guest read %#x, want %#x", i, got, marker+uint64(i))
		}
		as.Release()
		if err := memutil.UnmapView(arena); err != nil {
			t.Fatalf("iteration %d: UnmapView: %v", i, err)
		}
	}

	runOnce(0) // Warm up the slab and the worker.
	before, blocksBefore := vm.slabStats(), vm.hostBlockCount()
	for i := 1; i <= 400; i++ {
		runOnce(i)
	}
	after, blocksAfter := vm.slabStats(), vm.hostBlockCount()
	if after != before {
		t.Errorf("slab after 400 address spaces = %+v, want %+v: table pages leak", after, before)
	}
	if blocksAfter != blocksBefore {
		t.Errorf("host blocks after churn = %d, want %d: Stage-2 mappings leak", blocksAfter, blocksBefore)
	}
}

func TestUnmapStopsRunningVCPUsBeforeReturning(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnLdrX1X0, 0x17ffffff) // LDR X1,[X0]; B .-4
	g.regs().Regs[0] = uint64(guestDataAddr)
	for i := range 100 {
		res := g.switchAsync()
		waitInGuest(t, g.ctx)
		g.as.Unmap(guestDataAddr, pageSize4K)
		got := receive(t, res)
		if !errors.Is(got.err, platform.ErrContextSignal) || got.sig == nil || got.sig.Signo != int32(linux.SIGSEGV) {
			t.Fatalf("iteration %d: Switch = (%v, %v), want SIGSEGV after the unmap", i, got.sig, got.err)
		}
		if got.sig.Code != sigSegvMap || got.sig.Addr() != uint64(guestDataAddr) {
			t.Fatalf("iteration %d: signal code %d addr %#x, want SEGV_MAPERR at the data page", i, got.sig.Code, got.sig.Addr())
		}
		g.ac.SetIP(uintptr(guestCodeAddr))
		mapHostBytes(t, g.as, guestDataAddr, g.data, hostarch.ReadWrite)
	}
}

func TestReleaseOfRunningAddressSpaceStopsTheGuest(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnBSelf)
	res := g.switchAsync()
	waitInGuest(t, g.ctx)
	g.as.Release()
	got := receive(t, res)
	if !errors.Is(got.err, errPageTableReleased) {
		t.Fatalf("Switch after Release = (%v, %v), want errPageTableReleased", got.sig, got.err)
	}
	if _, _, err := g.switchOnce(); !errors.Is(err, errPageTableReleased) {
		t.Fatalf("second Switch = %v, want errPageTableReleased", err)
	}
}

func TestHostBlocksAreReferenceCounted(t *testing.T) {
	plat := newTestPlatform(t)
	vm := plat.vm
	base := vm.hostBlockCount()
	a := newGuest(t, plat)
	if got := vm.hostBlockCount(); got != base+1 {
		t.Fatalf("one arena maps %d blocks, want 1", got-base)
	}
	// A second address space maps the same host page: the block is shared.
	asIface, err := plat.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b := asIface.(*AddressSpace)
	mapHostBytes(t, b, guestCodeAddr, a.code, hostarch.Read)
	if got := vm.hostBlockCount(); got != base+1 {
		t.Fatalf("a second mapping of the same page maps %d blocks, want 1", got-base)
	}
	a.as.Unmap(guestCodeAddr, 2*pageSize4K)
	if got := vm.hostBlockCount(); got != base+1 {
		t.Fatalf("the block went away while the second address space references it (%d)", got-base)
	}
	b.Unmap(guestCodeAddr, pageSize4K)
	if got := vm.hostBlockCount(); got != base {
		t.Fatalf("%d blocks stay mapped after the last reference left", got-base)
	}
	b.Release()
}

func TestMapReplacementReleasesThePreviousBlock(t *testing.T) {
	plat := newTestPlatform(t)
	vm := plat.vm
	g := newGuest(t, plat)
	base := vm.hostBlockCount()
	other, err := memutil.AllocateAnonymousArena(hostPageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer memutil.UnmapView(other)
	mapHostBytes(t, g.as, guestDataAddr, other[:pageSize4K], hostarch.ReadWrite)
	if got := vm.hostBlockCount(); got != base+1 {
		t.Fatalf("blocks = %d, want %d: the replacement maps one new block", got, base+1)
	}
	// Replace it back: the replacement block must go away.
	mapHostBytes(t, g.as, guestDataAddr, g.data, hostarch.ReadWrite)
	if got := vm.hostBlockCount(); got != base {
		t.Fatalf("blocks = %d, want %d: the replaced mapping still holds its block", got, base)
	}
	binary.LittleEndian.PutUint64(g.data[8:], 0x1122)
	var buf [8]byte
	if _, err := g.as.CopyIn(guestDataAddr+8, buf[:]); err != nil || binary.LittleEndian.Uint64(buf[:]) != 0x1122 {
		t.Fatalf("CopyIn after replacement = %x, %v: the address space still sees the old page", buf, err)
	}
}

// testFile is a memmap.File whose MapInternal returns a fixed host slice.
type testFile struct {
	memmap.File
	mem []byte
}

func (f *testFile) MapInternal(fr memmap.FileRange, _ hostarch.AccessType) (safemem.BlockSeq, error) {
	return safemem.BlockSeqOf(safemem.BlockFromSafeSlice(f.mem[fr.Start:fr.End])), nil
}

func TestReadOnlyFileDescriptorMappingUsesACopy(t *testing.T) {
	plat := newTestPlatform(t)
	vm := plat.vm

	f, err := os.CreateTemp(t.TempDir(), "image")
	if err != nil {
		t.Fatal(err)
	}
	content := make([]byte, hostPageSize)
	binary.LittleEndian.PutUint64(content[0:], 0xfeedc0de)
	if _, err := f.WriteAt(content, 0); err != nil {
		t.Fatal(err)
	}
	f.Close()
	ro, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	mem, err := unix.Mmap(int(ro.Fd()), 0, hostPageSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mem)

	g := newGuest(t, plat, insnLdrX1X0, insnSVC0)
	base := vm.slabStats()
	file := &testFile{mem: mem}
	fr := memmap.FileRange{Start: 0, End: pageSize4K}
	if err := g.as.MapFile(guestDataAddr+0x10000, file, fr, hostarch.Read, false); err != nil {
		t.Fatalf("read-only MapFile: %v", err)
	}
	if got := vm.slabStats().pagesInUse; got <= base.pagesInUse {
		t.Errorf("slab pages in use = %d: the read-only descriptor mapping did not use a copy", got)
	}
	g.regs().Regs[0] = uint64(guestDataAddr) + 0x10000
	if sig, _, err := g.switchOnce(); sig != nil || err != nil {
		t.Fatalf("Switch = (%v, %v)", sig, err)
	}
	if got := g.regs().Regs[1]; got != 0xfeedc0de {
		t.Errorf("the guest read %#x, want the file content 0xfeedc0de", got)
	}

	// A writable mapping of the same memory must fail: a copy would diverge.
	err = g.as.MapFile(guestDataAddr+0x20000, file, fr, hostarch.ReadWrite, false)
	if !errors.Is(err, errHostBlockRejected) {
		t.Errorf("writable MapFile of read-only memory = %v, want errHostBlockRejected", err)
	}
	g.as.Unmap(guestDataAddr+0x10000, pageSize4K)
	if got := vm.slabStats().pagesInUse; got != base.pagesInUse {
		t.Errorf("slab pages in use = %d after the unmap, want %d: the copy leaked", got, base.pagesInUse)
	}
}

// The Sentry maps whole hostarch pages: 4KB by default and 16KB in a
// pagesize_16k build. The Stage-1 granule stays 4KB, so one MapFile call must
// install every 4KB page of the range.
func TestMapFileCoversWholeHostarchPages(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat)
	const pages = 4
	size := uint64(pages * hostarch.PageSize)
	mem, err := memutil.AllocateAnonymousArena(int(size))
	if err != nil {
		t.Fatal(err)
	}
	defer memutil.UnmapView(mem)
	for i := 0; i < len(mem); i += pageSize4K {
		mem[i] = byte(i/pageSize4K + 1)
		mem[i+pageSize4K-1] = byte(0xf0 + i/pageSize4K%16)
	}
	base := hostarch.Addr(0x1000000)
	if err := g.as.MapFile(base, &testFile{mem: mem}, memmap.FileRange{Start: 0, End: size}, hostarch.ReadWrite, false); err != nil {
		t.Fatalf("MapFile of %d bytes: %v", size, err)
	}
	got := make([]byte, size)
	if n, err := g.as.CopyIn(base, got); err != nil || uint64(n) != size {
		t.Fatalf("CopyIn = (%d, %v), want %d bytes", n, err, size)
	}
	if string(got) != string(mem) {
		t.Fatal("the address space does not alias the mapped memory")
	}
}

func TestMapFileRejectsUnalignedRanges(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat)
	file := &testFile{mem: g.arena}
	var segv platform.SegmentationFault
	for _, tc := range []struct {
		name string
		addr hostarch.Addr
		fr   memmap.FileRange
	}{
		{"unaligned address", guestDataAddr + 8, memmap.FileRange{Start: 0, End: pageSize4K}},
		{"unaligned start", guestDataAddr + 0x10000, memmap.FileRange{Start: 8, End: pageSize4K}},
		{"unaligned end", guestDataAddr + 0x10000, memmap.FileRange{Start: 0, End: 100}},
		{"empty range", guestDataAddr + 0x10000, memmap.FileRange{Start: 0, End: 0}},
	} {
		if err := g.as.MapFile(tc.addr, file, tc.fr, hostarch.Read, false); !errors.As(err, &segv) {
			t.Errorf("%s: MapFile = %v, want SegmentationFault", tc.name, err)
		}
	}
}

func TestMoreContextsThanVCPUsAllMakeProgress(t *testing.T) {
	plat := newTestPlatform(t)
	limitWorkers(t, plat, 3)
	const contexts, rounds = 10, 3
	guests := make([]*guest, contexts)
	for i := range guests {
		guests[i] = newGuest(t, plat, insnBSelf)
	}
	var wg sync.WaitGroup
	var finished atomic.Int32
	errs := make(chan error, contexts)
	for _, g := range guests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer finished.Add(1)
			for range rounds {
				if _, _, err := g.switchOnce(); !errors.Is(err, platform.ErrContextInterrupt) {
					errs <- err
					return
				}
			}
		}()
	}
	// The kernel preempts running tasks when more run than vCPUs exist.
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		for finished.Load() < contexts {
			for _, g := range guests {
				g.ctx.Preempt()
			}
			runtime.Gosched()
		}
	}()
	wg.Wait()
	<-stop
	close(errs)
	for err := range errs {
		t.Errorf("a Switch returned %v, want ErrContextInterrupt", err)
	}
	if got := plat.ConcurrencyCount(); got != 3 {
		t.Errorf("ConcurrencyCount() = %d, want the vCPU limit 3", got)
	}
}

func TestInterruptEndsAWaitForAVCPU(t *testing.T) {
	plat := newTestPlatform(t)
	limitWorkers(t, plat, 1)
	hog := newGuest(t, plat, insnBSelf)
	waiter := newGuest(t, plat, insnSVC0)
	hogRes := hog.switchAsync()
	waitInGuest(t, hog.ctx)

	waitRes := waiter.switchAsync()
	// The waiter blocks: the only vCPU runs the hog. Wait until it queued.
	for {
		plat.vm.pool.mu.Lock()
		queued := len(plat.vm.pool.waiters)
		plat.vm.pool.mu.Unlock()
		if queued == 1 {
			break
		}
		runtime.Gosched()
	}
	waiter.ctx.Interrupt()
	got := receive(t, waitRes)
	if !errors.Is(got.err, platform.ErrContextInterrupt) {
		t.Fatalf("waiting Switch = (%v, %v), want ErrContextInterrupt", got.sig, got.err)
	}
	hog.ctx.Interrupt()
	if got := receive(t, hogRes); !errors.Is(got.err, platform.ErrContextInterrupt) {
		t.Fatalf("hog Switch = (%v, %v)", got.sig, got.err)
	}
}

func TestCloseDestroysVCPUsAndTheVM(t *testing.T) {
	for i := range 8 {
		p, err := New()
		if err != nil {
			t.Fatalf("iteration %d: New: %v", i, err)
		}
		g := newGuest(t, p, insnSVC0)
		if sig, _, err := g.switchOnce(); sig != nil || err != nil {
			t.Fatalf("iteration %d: Switch = (%v, %v)", i, sig, err)
		}
		g.as.Release()
		if err := p.Close(); err != nil {
			t.Fatalf("iteration %d: Close: %v", i, err)
		}
		if err := p.Close(); err != nil {
			t.Fatalf("iteration %d: second Close: %v", i, err)
		}
		// hv_vm_create fails with HV_BUSY while the old VM or any vCPU exists.
		if err := hvVMCreate(); err != nil {
			t.Fatalf("iteration %d: the VM survived Close: %v", i, err)
		}
		if err := hvVMDestroy(); err != nil {
			t.Fatalf("iteration %d: hv_vm_destroy: %v", i, err)
		}
	}
}

func TestPlatformsShareOneVMUntilTheLastCloses(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if a.vm != b.vm {
		t.Fatal("two Platforms hold different VMs")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	g := newGuest(t, b, insnSVC0)
	if sig, _, err := g.switchOnce(); sig != nil || err != nil {
		t.Fatalf("Switch on the surviving Platform = (%v, %v)", sig, err)
	}
	g.as.Release()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUseAfterCloseFailsExplicitly(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	g := newGuest(t, p, insnSVC0)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.switchOnce(); !errors.Is(err, errPlatformClosed) {
		t.Errorf("Switch after Close = %v, want errPlatformClosed", err)
	}
	if _, err := p.NewAddressSpace(platform.AddressSpaceOptions{}); !errors.Is(err, errPlatformClosed) {
		t.Errorf("NewAddressSpace after Close = %v, want errPlatformClosed", err)
	}
	mem, err := memutil.AllocateAnonymousArena(hostPageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer memutil.UnmapView(mem)
	var stale []pageEntry
	g.as.mu.Lock()
	err = g.as.mapPageLocked(0x800000, mem[:pageSize4K:pageSize4K], hostarch.Read, &stale)
	g.as.mu.Unlock()
	if !errors.Is(err, errPlatformClosed) {
		t.Errorf("mapping after Close = %v, want errPlatformClosed", err)
	}
	// Releasing an address space after Close must not touch freed memory.
	g.as.Release()
}

func TestCloseStopsAGuestThatIsRunning(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	g := newGuest(t, p, insnBSelf)
	res := g.switchAsync()
	waitInGuest(t, g.ctx)
	if err := p.Close(); err != nil {
		t.Fatalf("Close with a running guest: %v", err)
	}
	if got := receive(t, res); !errors.Is(got.err, errPlatformClosed) {
		t.Fatalf("Switch = (%v, %v), want errPlatformClosed", got.sig, got.err)
	}
}

func TestCloseRacingWithSwitchNeverHangs(t *testing.T) {
	for i := range 60 {
		p, err := New()
		if err != nil {
			t.Fatalf("iteration %d: New: %v", i, err)
		}
		const guests = 6
		var results [guests]<-chan switchResult
		for j := range guests {
			g := newGuest(t, p, insnSVC0, 0x17ffffff) // SVC #0; B .-4
			ch := make(chan switchResult, 1)
			results[j] = ch
			go func() {
				// Run system calls until the Platform stops the Context.
				for {
					sig, at, err := g.switchOnce()
					if err != nil || sig != nil {
						ch <- switchResult{sig, at, err}
						return
					}
					g.ac.SetIP(uintptr(guestCodeAddr))
				}
			}()
		}
		if err := p.Close(); err != nil {
			t.Fatalf("iteration %d: Close: %v", i, err)
		}
		for j, ch := range results {
			got := receive(t, ch)
			if !errors.Is(got.err, errPlatformClosed) {
				t.Fatalf("iteration %d guest %d: Switch ended with (%v, %v), want errPlatformClosed", i, j, got.sig, got.err)
			}
		}
	}
}

func TestPlatformRegistrationAndLimits(t *testing.T) {
	ctor, err := platform.Lookup(PlatformName)
	if err != nil {
		t.Fatalf("platform.Lookup(%q): %v", PlatformName, err)
	}
	p, err := ctor.New(platform.Options{})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	plat := p.(*Platform)
	defer plat.Close()
	if got := plat.MapUnit(); got != hostarch.PageSize {
		t.Errorf("MapUnit() = %d, want hostarch.PageSize %d", got, hostarch.PageSize)
	}
	if !FrameworkSymbolsLoaded() {
		t.Error("FrameworkSymbolsLoaded() = false")
	}
	if n := plat.ConcurrencyCount(); n < 1 || n > kernelCommPages {
		t.Errorf("ConcurrencyCount() = %d, want 1..%d", n, kernelCommPages)
	}
	if got := plat.MaxUserAddress(); got != 1<<48 {
		t.Errorf("MaxUserAddress() = %#x", uint64(got))
	}
}
