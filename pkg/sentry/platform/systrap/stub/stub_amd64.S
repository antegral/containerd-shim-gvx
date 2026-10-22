// Entry and exit of a guest thread of the macOS amd64 stub. Rosetta translates
// this code, like the rest of the stub.

#include "gvx_stub_amd64.h"

.text

// gv_thread_entry is the start routine of a guest thread. It keeps the
// callee-saved registers of libpthread in its own frame, because the guest
// overwrites them. It publishes the frame in the sysmsg through gv_thread_run,
// so that the exit path of the signal handler can come back here and return to
// libpthread in an ordinary way.
.globl _gv_thread_entry
.p2align 4
_gv_thread_entry:
    pushq %rbp
    movq  %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq  $8, %rsp
    movq  %rsp, %rsi
    call  _gv_thread_run
    jmp   _gv_thread_unwind_body

// gv_thread_unwind is the target of the signal handler when the Sentry ends a
// thread. The handler sets RSP to the frame that gv_thread_entry published.
.globl _gv_thread_unwind
.p2align 4
_gv_thread_unwind:
    xorl  %eax, %eax
_gv_thread_unwind_body:
    addq  $8, %rsp
    popq  %r15
    popq  %r14
    popq  %r13
    popq  %r12
    popq  %rbx
    popq  %rbp
    ret
