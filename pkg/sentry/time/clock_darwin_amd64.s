//go:build darwin && amd64

#include "textflag.h"

TEXT ·clockGettimeNsecNpTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_clock_gettime_nsec_np(SB)

TEXT ·addrOfClockGettimeNsecNp(SB),NOSPLIT,$0-8
	LEAQ	·clockGettimeNsecNpTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
