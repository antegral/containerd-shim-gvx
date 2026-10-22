//go:build darwin && arm64

#include "textflag.h"

TEXT ·ulockWaitTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_ulock_wait(SB)

TEXT ·addrOfUlockWait(SB),NOSPLIT,$0-8
	MOVD	$·ulockWaitTrampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·ulockWakeTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_ulock_wake(SB)

TEXT ·addrOfUlockWake(SB),NOSPLIT,$0-8
	MOVD	$·ulockWakeTrampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET
