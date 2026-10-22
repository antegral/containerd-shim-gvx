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

//go:build darwin && amd64

#include "textflag.h"

TEXT ·taskSelfTrapTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_task_self_trap(SB)

TEXT ·addrOfTaskSelfTrap(SB),NOSPLIT,$0-8
	LEAQ	·taskSelfTrapTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·machVMRemapWrapperTrampoline(SB),NOSPLIT,$0-0
	SUBQ	$40, SP
	MOVQ	CX, 0(SP)
	MOVQ	$0, 8(SP)
	MOVQ	R8, 16(SP)
	MOVQ	R9, 24(SP)
	MOVQ	$0, 32(SP)
	MOVQ	DI, R9
	MOVQ	$1, R8
	MOVQ	$0, CX
	CALL	libc_mach_vm_remap(SB)
	ADDQ	$40, SP
	RET

TEXT ·addrOfMachVMRemapWrapper(SB),NOSPLIT,$0-8
	LEAQ	·machVMRemapWrapperTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
