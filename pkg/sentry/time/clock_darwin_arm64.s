//go:build darwin && arm64

#include "textflag.h"

TEXT ·clockGettimeNsecNpTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_clock_gettime_nsec_np(SB)

TEXT ·addrOfClockGettimeNsecNp(SB),NOSPLIT,$0-8
	MOVD	$·clockGettimeNsecNpTrampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET
