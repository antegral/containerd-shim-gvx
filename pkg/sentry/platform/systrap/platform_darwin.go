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

// The darwin/arm64 systrap backend runs guest code natively in separate stub
// tasks. Each AddressSpace is one stub task, forked from a template process
// that the Sentry spawns before it locks itself down. A guest thread is a Mach
// thread of the stub task. The Sentry and the thread exchange registers
// through a sysmsg page that both map, and wake each other with __ulock.
//
// Three macOS facts shape the design. The stub image is a normal dyld-linked
// Mach-O, because the kernel kills a static arm64 executable. Every arm64 task
// has a 4GB PAGEZERO, so guest addresses start above 4GB. The kernel runs a
// guest `svc #0` as a host system call and clobbers TPIDR_EL0 and X18, so the
// patcher rewrites those instructions. See patcher_arm64_xplat.go.
package systrap

import (
	"fmt"
	"math"
	"sync"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/interrupt"
)

const (
	// userFloor is the lowest address that a guest may ever use. The stub
	// image, its heap, dyld and the shared cache occupy the range from 4GB to
	// 12GB. The constant leaves room for their ASLR slide. It also keeps
	// ET_EXEC guests, which link at 0x400000, out of an address space that
	// cannot hold them. The Platform raises the real limit above every
	// reservation of the host kernel. See userRangeFromRegions.
	userFloor = 0x4_0000_0000

	// sysBase is the first address of the per-thread sysmsg blocks in a stub
	// task. Guests cannot map at or above it.
	sysBase = 0x7fff_c000_0000

	// sysSize bounds the guest threads of one stub task.
	sysSize = 0x1000_0000

	// maxThreadBlocks is the number of sysmsg blocks that fit in sysSize.
	maxThreadBlocks = sysSize / threadSpan
)

// ErrUnsupportedPageSize reports a build whose guest page size differs from
// the 16KB host VM page size.
type ErrUnsupportedPageSize struct {
	// GuestPage is hostarch.PageSize.
	GuestPage int
	// HostPage is the host VM page size.
	HostPage int
}

// Error implements error.
func (e *ErrUnsupportedPageSize) Error() string {
	return fmt.Sprintf("systrap on darwin/arm64 needs hostarch.PageSize == host VM page size (%dKB): build with -tags pagesize_16k (hostarch.PageSize is %d, host page size is %d)",
		e.HostPage/1024, e.GuestPage, e.HostPage)
}

// Platform implements platform.Platform with native stub tasks.
type Platform struct {
	platform.NoCPUPreemptionDetection
	platform.NoCPUNumbers
	platform.UseHostProcessMemoryBarrier

	pool *pagePool
	host *stubHost

	// userMin and userMax bound the guest address range. No host mapping lies
	// in [userMin, userMax), so every guest mapping in that range succeeds.
	userMin, userMax uint64

	// images caches the headers of the files that guests map as code.
	images imageCache

	closeOnce sync.Once
	closeErr  error
}

var (
	configureOnce sync.Once
)

// New spawns the template stub process and returns a Platform. It must run
// before the Sentry locks itself down.
func New() (*Platform, error) {
	if host := unix.Getpagesize(); hostarch.PageSize != blockSize || host != blockSize {
		return nil, &ErrUnsupportedPageSize{GuestPage: hostarch.PageSize, HostPage: host}
	}
	configureOnce.Do(func() { arch.ConfigureAddressSpace(1 << 48) })
	pool := newPagePool()
	host, err := spawnStubHost(pool)
	if err != nil {
		_ = pool.close()
		return nil, err
	}
	userMin, userMax, err := host.userRange()
	if err != nil {
		_ = host.close()
		_ = pool.close()
		return nil, err
	}
	return &Platform{pool: pool, host: host, userMin: userMin, userMax: userMax}, nil
}

// regionLister reports the first mapping that ends above addr.
type regionLister func(addr uint64) (hostRegion, bool, error)

// userRangeFromRegions returns the widest guest address range that starts above
// every permanent host reservation and ends before the next mapping of the stub
// task or at sysBase.
//
// WHY: macOS gives every process permanent PROT_NONE reservations. On Apple
// silicon they cover the 385GB range from 0xfc0000000 to 0x7000000000, and
// they survive mach_vm_deallocate. A guest mapping there fails on the host
// after the Sentry accepted it, and the guest dies with SIGBUS. V8 picks random
// mmap hints and hits the range in about one run in eight. The stub task also
// holds ordinary mappings, such as malloc zones, which macOS 15 places near
// 0x600000000000. A guest mapping over one of them would replace it. The
// stub cannot allocate after its sandbox starts, so these mappings never
// move. The Sentry has no way to describe a hole inside the user address
// range, so the range starts above the last reservation and ends at the first
// mapping above that. The layout differs between macOS releases and machines,
// so the Platform reads it from the template task.
func userRangeFromRegions(list regionLister) (lo, hi uint64, err error) {
	var regions []hostRegion
	for addr := uint64(userFloor); addr < sysBase; {
		r, ok, err := list(addr)
		if err != nil {
			return 0, 0, err
		}
		if !ok || r.start >= sysBase {
			break
		}
		if r.size == 0 {
			return 0, 0, fmt.Errorf("mach_vm_region returned an empty region at %#x", r.start)
		}
		regions = append(regions, r)
		addr = r.start + r.size
	}
	lo = userFloor
	for _, r := range regions {
		if r.reserved && r.start+r.size > lo {
			lo = r.start + r.size
		}
	}
	lo = (lo + blockSize - 1) &^ (blockSize - 1)
	hi = sysBase
	for _, r := range regions {
		if r.start >= lo {
			hi = r.start &^ (blockSize - 1)
			break
		}
	}
	if hi <= lo {
		return 0, 0, fmt.Errorf("the host leaves no guest address range between %#x and %#x", lo, hi)
	}
	return lo, hi, nil
}

// Close terminates every stub task and frees the Sentry-side memory. It is
// idempotent. No AddressSpace of this Platform may be used afterwards.
func (p *Platform) Close() error {
	p.closeOnce.Do(func() {
		err := p.host.close()
		if perr := p.pool.close(); err == nil {
			err = perr
		}
		p.closeErr = err
	})
	return p.closeErr
}

// SupportsAddressSpaceIO implements platform.Platform.SupportsAddressSpaceIO.
// The guest memory lives in another task, so the Sentry reaches it through the
// memory file only.
func (*Platform) SupportsAddressSpaceIO() bool { return false }

// MapUnit implements platform.Platform.MapUnit.
func (*Platform) MapUnit() uint64 { return blockSize }

// MinUserAddress implements platform.Platform.MinUserAddress.
func (p *Platform) MinUserAddress() hostarch.Addr { return hostarch.Addr(p.userMin) }

// MaxUserAddress implements platform.Platform.MaxUserAddress.
func (p *Platform) MaxUserAddress() hostarch.Addr { return hostarch.Addr(p.userMax) }

// NewAddressSpace implements platform.Platform.NewAddressSpace. The platform
// patches syscalls always, so the DisableSyscallPatching option has no effect.
func (p *Platform) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return newAddressSpace(p)
}

// NewContext implements platform.Platform.NewContext.
func (p *Platform) NewContext(context.Context) platform.Context {
	c := &Context{p: p}
	c.interrupt = interrupt.Forwarder{Dst: c}
	return c
}

// SeccompInfo implements platform.Platform.SeccompInfo.
func (*Platform) SeccompInfo() platform.SeccompInfo {
	return platform.StaticSeccompInfo{PlatformName: PlatformName}
}

// ConcurrencyCount implements platform.Platform.ConcurrencyCount. Each guest
// thread has its own host thread, so the platform never makes Switch wait.
func (*Platform) ConcurrencyCount() int { return math.MaxInt }
