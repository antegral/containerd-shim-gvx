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

package hostcpu

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procGetCurrentProcessorNumberEx   = modKernel32.NewProc("GetCurrentProcessorNumberEx")
	procGetMaximumProcessorGroupCount = modKernel32.NewProc("GetMaximumProcessorGroupCount")
	procGetMaximumProcessorCount      = modKernel32.NewProc("GetMaximumProcessorCount")
)

// processorNumber is PROCESSOR_NUMBER from winnt.h.
type processorNumber struct {
	Group    uint16
	Number   uint8
	Reserved uint8
}

// processorLayout lists the processor groups of the host. Windows numbers a
// processor within its group, so a flat CPU index adds the sizes of the earlier groups.
type processorLayout struct {
	firstCPU []uint32 // Flat index of the first processor of each group.
	size     []uint32 // Largest processor count of each group.
	total    uint32
}

// hostLayout reads the group sizes once. The maximum counts include
// processors that Windows can hot-add, so a flat index never exceeds MaxPossibleCPU.
var hostLayout = sync.OnceValues(func() (processorLayout, error) {
	groups, _, err := procGetMaximumProcessorGroupCount.Call()
	if groups == 0 {
		return processorLayout{}, fmt.Errorf("GetMaximumProcessorGroupCount: %w", err)
	}
	var layout processorLayout
	for group := uintptr(0); group < groups; group++ {
		count, _, err := procGetMaximumProcessorCount.Call(group)
		if count == 0 {
			return processorLayout{}, fmt.Errorf("GetMaximumProcessorCount(group %d): %w", group, err)
		}
		layout.firstCPU = append(layout.firstCPU, layout.total)
		layout.size = append(layout.size, uint32(count))
		layout.total += uint32(count)
	}
	return layout, nil
})

var errCPUOutOfRange = errors.New("host reported a processor outside the processor groups")

// currentCPU returns the flat index of the processor that the calling thread runs on.
// The thread can move to another processor before the caller uses the result.
//
// GetCurrentProcessorNumberEx is the processor-group-aware form of
// GetCurrentProcessorNumber. The older call returns only the number inside the
// group, which collides across groups on hosts with more than 64 logical processors.
func currentCPU() (uint32, error) {
	layout, err := hostLayout()
	if err != nil {
		return 0, err
	}
	var pn processorNumber
	// The call has no return value and cannot fail.
	_, _, _ = procGetCurrentProcessorNumberEx.Call(uintptr(unsafe.Pointer(&pn)))
	group := int(pn.Group)
	if group >= len(layout.size) || uint32(pn.Number) >= layout.size[group] {
		return 0, fmt.Errorf("%w: group=%d number=%d", errCPUOutOfRange, pn.Group, pn.Number)
	}
	return layout.firstCPU[group] + uint32(pn.Number), nil
}

// GetCPU returns the caller's current processor index across all processor groups.
// It panics if the host reports a processor outside its groups. Callers index
// per-CPU state with the result, and a folded number would hide the fault.
func GetCPU() uint32 {
	cpu, err := currentCPU()
	if err != nil {
		panic(fmt.Sprintf("hostcpu: cannot read the current CPU: %v", err))
	}
	return cpu
}

// MaxPossibleCPU returns the highest flat processor index across all processor groups.
func MaxPossibleCPU() (uint32, error) {
	layout, err := hostLayout()
	if err != nil {
		return 0, err
	}
	return layout.total - 1, nil
}
