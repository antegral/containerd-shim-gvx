//go:build darwin && arm64

#include "textflag.h"

TEXT ·pthreadCPUNumberTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_pthread_cpu_number_np(SB)

TEXT ·addrOfPthreadCPUNumber(SB),NOSPLIT,$0-8
	MOVD	$·pthreadCPUNumberTrampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET
