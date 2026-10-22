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

// libcCallTramp is a C-ABI function for syscall.syscall6. It loads twelve
// argument words and calls the libSystem function in its first argument.
// Arguments 0 to 7 travel in registers and arguments 8 to 11 in 8-byte stack slots.
TEXT ·libcCallTramp(SB),NOSPLIT|NOFRAME,$0-0
	STP.W	(R29, R30), -16(RSP)
	MOVD	R0, R9
	MOVD	R1, R10
	SUB	$32, RSP
	MOVD	64(R10), R11
	MOVD	R11, 0(RSP)
	MOVD	72(R10), R11
	MOVD	R11, 8(RSP)
	MOVD	80(R10), R11
	MOVD	R11, 16(RSP)
	MOVD	88(R10), R11
	MOVD	R11, 24(RSP)
	MOVD	0(R10), R0
	MOVD	8(R10), R1
	MOVD	16(R10), R2
	MOVD	24(R10), R3
	MOVD	32(R10), R4
	MOVD	40(R10), R5
	MOVD	48(R10), R6
	MOVD	56(R10), R7
	BL	(R9)
	ADD	$32, RSP
	LDP.P	16(RSP), (R29, R30)
	RET

TEXT ·addrOfLibcCall(SB),NOSPLIT,$0-8
	MOVD	$·libcCallTramp(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·dlsymTramp(SB),NOSPLIT|NOFRAME,$0-0
	JMP	libc_dlsym(SB)

TEXT ·addrOfDlsym(SB),NOSPLIT,$0-8
	MOVD	$·dlsymTramp(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·taskSelfTrampoline(SB),NOSPLIT|NOFRAME,$0-0
	JMP	libc_task_self_trap(SB)

TEXT ·addrOfTaskSelf(SB),NOSPLIT,$0-8
	MOVD	$·taskSelfTrampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET
