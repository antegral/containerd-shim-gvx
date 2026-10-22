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

// libcCallTramp is a C-ABI function for syscall.syscall6. The runtime puts the
// target function in DI and the argument array in SI. The function loads twelve
// argument words and calls the target. Words 0 to 5 travel in DI, SI, DX, CX,
// R8 and R9. Words 6 to 11 travel in 8-byte stack slots.
//
// On entry the stack is 8 bytes below a 16-byte boundary because of the return
// address. The saved frame pointer restores the boundary. The 48-byte
// argument area keeps it, so the CALL sees an aligned stack.
TEXT ·libcCallTramp(SB),NOSPLIT|NOFRAME,$0-0
	PUSHQ	BP
	MOVQ	SP, BP
	SUBQ	$48, SP
	MOVQ	DI, R11
	MOVQ	SI, R10
	MOVQ	48(R10), AX
	MOVQ	AX, 0(SP)
	MOVQ	56(R10), AX
	MOVQ	AX, 8(SP)
	MOVQ	64(R10), AX
	MOVQ	AX, 16(SP)
	MOVQ	72(R10), AX
	MOVQ	AX, 24(SP)
	MOVQ	80(R10), AX
	MOVQ	AX, 32(SP)
	MOVQ	88(R10), AX
	MOVQ	AX, 40(SP)
	MOVQ	0(R10), DI
	MOVQ	8(R10), SI
	MOVQ	16(R10), DX
	MOVQ	24(R10), CX
	MOVQ	32(R10), R8
	MOVQ	40(R10), R9
	// AL holds the vector register count for variadic callees.
	XORL	AX, AX
	CALL	R11
	MOVQ	BP, SP
	POPQ	BP
	RET

TEXT ·addrOfLibcCall(SB),NOSPLIT,$0-8
	LEAQ	·libcCallTramp(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·dlsymTramp(SB),NOSPLIT|NOFRAME,$0-0
	JMP	libc_dlsym(SB)

TEXT ·addrOfDlsym(SB),NOSPLIT,$0-8
	LEAQ	·dlsymTramp(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·taskSelfTrampoline(SB),NOSPLIT|NOFRAME,$0-0
	JMP	libc_task_self_trap(SB)

TEXT ·addrOfTaskSelf(SB),NOSPLIT,$0-8
	LEAQ	·taskSelfTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
