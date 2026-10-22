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

#include "textflag.h"

TEXT ·taskSelfTrapTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_task_self_trap(SB)

TEXT ·addrOfTaskSelfTrap(SB),NOSPLIT,$0-8
	MOVD	$·taskSelfTrapTrampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·machVMRemapWrapperTrampoline(SB),NOSPLIT,$0-0
	SUB	$32, RSP
	MOVD	R30, 24(RSP)
	MOVD	R4, 0(RSP)
	MOVD	R5, 8(RSP)
	MOVD	ZR, 16(RSP)
	MOVD	R3, R6
	MOVD	R0, R5
	MOVD	$1, R4
	MOVD	ZR, R3
	MOVD	ZR, R7
	BL	libc_mach_vm_remap(SB)
	MOVD	24(RSP), R30
	ADD	$32, RSP
	RET

TEXT ·addrOfMachVMRemapWrapper(SB),NOSPLIT,$0-8
	MOVD	$·machVMRemapWrapperTrampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET
