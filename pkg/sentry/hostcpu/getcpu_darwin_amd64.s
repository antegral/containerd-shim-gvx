//go:build darwin && amd64

#include "textflag.h"

TEXT ·pthreadCPUNumberTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_pthread_cpu_number_np(SB)

TEXT ·addrOfPthreadCPUNumber(SB),NOSPLIT,$0-8
	LEAQ	·pthreadCPUNumberTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
