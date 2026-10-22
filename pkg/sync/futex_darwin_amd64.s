//go:build darwin && amd64

#include "textflag.h"

TEXT ·ulockWaitTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_ulock_wait(SB)

TEXT ·addrOfUlockWait(SB),NOSPLIT,$0-8
	LEAQ	·ulockWaitTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·ulockWakeTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_ulock_wake(SB)

TEXT ·addrOfUlockWake(SB),NOSPLIT,$0-8
	LEAQ	·ulockWakeTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
