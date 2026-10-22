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

// func readSystemCounter() uint64
// ISB keeps the counter read from executing early. The WORD is MRS X0, CNTPCT_EL0.
TEXT ·readSystemCounter(SB), NOSPLIT, $0-8
	ISB	$15
	WORD	$0xd53be020
	MOVD	R0, ret+0(FP)
	RET
