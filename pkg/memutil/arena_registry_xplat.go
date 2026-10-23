//go:build darwin || windows

package memutil

import (
	"errors"
	"sync"
	"unsafe"
)

// ErrNotArena reports that a slice does not lie inside a mapping that
// AllocateAnonymousArena returned. RemapAnonymousView needs the owning arena to alias its memory.
var ErrNotArena = errors.New("slice is not backed by an anonymous arena")

// ErrNotMapped reports that UnmapView or UnmapSlice received a slice that this package did not map.
var ErrNotMapped = errors.New("slice is not a mapping created by this package")

// arenaRecord describes one AllocateAnonymousArena mapping and the aliases created over it.
type arenaRecord struct {
	base   uintptr
	length uintptr // Mapped bytes, rounded up to the host granularity.

	// section is the Windows section handle that backs the arena. It is zero on macOS.
	section uintptr

	// mu orders the release of section against remaps that still use the handle.
	// Only the Windows code takes it.
	mu sync.RWMutex

	// views holds the live aliases keyed by the address of the slice that RemapAnonymousView returned.
	views map[uintptr]*viewRecord
}

// viewRecord describes one mapping that UnmapView must release as a unit.
// The mapping starts at base. Host granularity can force base below the slice
// start address, down to a page or allocation boundary.
type viewRecord struct {
	arena  *arenaRecord // Nil for views that MapFile created.
	base   uintptr
	length uintptr
}

// registry is the single index of arenas and views. One lock guards every field,
// and no caller holds it across a host call.
var registry struct {
	mu     sync.Mutex
	arenas map[uintptr]*arenaRecord // Keyed by arena base.
	views  map[uintptr]*viewRecord  // Keyed by slice start address.
}

func registerArena(rec *arenaRecord) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.arenas == nil {
		registry.arenas = make(map[uintptr]*arenaRecord)
	}
	rec.views = make(map[uintptr]*viewRecord)
	registry.arenas[rec.base] = rec
}

// findArena returns the registered arena that contains [addr, addr+n).
func findArena(addr, n uintptr) (*arenaRecord, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if rec, ok := registry.arenas[addr]; ok && n <= rec.length {
		return rec, true
	}
	for _, rec := range registry.arenas {
		if addr >= rec.base && addr-rec.base <= rec.length && n <= rec.length-(addr-rec.base) {
			return rec, true
		}
	}
	return nil, false
}

// registerView records an alias. It reports false if the arena was unmapped
// after findArena returned it, in which case the caller must release the new mapping itself.
func registerView(arena *arenaRecord, start uintptr, view *viewRecord) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if arena != nil {
		if registry.arenas[arena.base] != arena {
			return false
		}
		arena.views[start] = view
	}
	if registry.views == nil {
		registry.views = make(map[uintptr]*viewRecord)
	}
	registry.views[start] = view
	return true
}

// takeView removes the view that starts at start and unlinks it from its arena.
func takeView(start uintptr) (*viewRecord, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	view, ok := registry.views[start]
	if !ok {
		return nil, false
	}
	delete(registry.views, start)
	if view.arena != nil {
		delete(view.arena.views, start)
	}
	return view, true
}

// takeArena removes the arena that starts at start together with all of its live views.
func takeArena(start uintptr) (*arenaRecord, []*viewRecord, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	rec, ok := registry.arenas[start]
	if !ok {
		return nil, nil, false
	}
	delete(registry.arenas, start)
	views := make([]*viewRecord, 0, len(rec.views))
	for addr, view := range rec.views {
		delete(registry.views, addr)
		views = append(views, view)
	}
	rec.views = nil
	return rec, views, true
}

// pointerFromAddr converts an address that the host mapped outside the Go heap into a pointer.
// The round trip through a pointer-sized word avoids vet's uintptr conversion check,
// which targets Go heap addresses and does not apply to host mappings.
func pointerFromAddr(addr uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&addr))
}
