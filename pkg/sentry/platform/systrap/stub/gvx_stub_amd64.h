// Shared layout between the macOS amd64 systrap stub and the Sentry.
// The stub runs translated by Rosetta 2. The Go side mirrors every constant in
// sysmsg_darwin_amd64.go and checks them against the layout table in the hello
// message at startup.

#ifndef GVX_STUB_AMD64_H
#define GVX_STUB_AMD64_H

// Host VM page size inside a translated task, and the span of one guest thread.
// The span holds the sysmsg page, the private C stack of the host thread and
// the signal alternate stack. The alternate stack ends at the span end, so a
// signal handler finds its sysmsg by masking the stack pointer.
#define GV_BLOCK_SIZE 0x1000
#define GV_THREAD_SPAN 0x10000
#define GV_SYSMSG_SIZE 0x1000
#define GV_STACK_BASE 0x1000
#define GV_STACK_TOP 0x8000
#define GV_ALTSTACK_BASE 0x8000
#define GV_ALTSTACK_TOP 0x10000

// Protocol states of gv_sysmsg.state.
#define GV_ST_NEW 0
#define GV_ST_TRAPPED 2
#define GV_ST_RUN 3
#define GV_ST_COLD 4
#define GV_ST_EXIT 5

// Reasons that gv_sysmsg.kind reports when the state becomes TRAPPED.
#define GV_KIND_START 1
#define GV_KIND_SIGNAL 3
#define GV_KIND_INTERRUPT 4

#define GV_MAGIC 0x3174737876673031ULL
#define GV_HELLO_MAGIC 0x6f6c6c6568767667ULL
#define GV_PROTOCOL_VERSION 2

// Commands for the template process and for a forked stub task.
#define GV_CMD_FORK 1
#define GV_CMD_EXIT 2
#define GV_CMD_KILL 3
#define GV_CMD_THREAD 4
#define GV_CMD_KICK 5
#define GV_CMD_JOIN 6

// Offsets inside struct gv_sysmsg.
#define SM_MAGIC 0
#define SM_STATE 8
#define SM_KIND 12
#define SM_SIG 16
#define SM_ADDR 24
#define SM_CODE 32
#define SM_TRAPNO 40
#define SM_ERR 44
#define SM_FAULT 48
#define SM_GSBASE 56
#define SM_GSAPPLIED 64
#define SM_COLD 72
#define SM_FPDIRTY 76
#define SM_NINVAL 80
#define SM_INVAL 88
#define SM_TSDBASE 136
#define SM_CTX 144
#define SM_HOSTSP 312
#define SM_FP 320

// Size of struct gv_ctx: the Darwin x86_thread_state64 in its native order.
#define CTX_SIZE 168
#define FP_SIZE 512

#ifndef __ASSEMBLER__

#include <stdint.h>

// One page run that the resumed thread passes through mprotect. The Rosetta
// runtime drops its cached translation of a page when the protection of the
// page changes inside the task, and it does not notice a change that another
// task makes. The thread sets the protection to tmp_prot and then to
// final_prot, so the two values must differ.
struct gv_inval {
  uint64_t addr;
  uint64_t len;
  uint32_t tmp_prot;
  uint32_t final_prot;
};

// x86_thread_state64_t of Darwin. Segment registers are selectors.
struct gv_ctx {
  uint64_t rax, rbx, rcx, rdx, rdi, rsi, rbp, rsp;
  uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
  uint64_t rip, rflags, cs, fs, gs;
};

#define GV_MAX_INVAL 2

// Number of guest threads that one stub task can hold.
#define GV_MAX_THREADS 4096

struct gv_sysmsg {
  uint64_t magic;      // SM_MAGIC
  uint32_t state;      // SM_STATE, the futex word of the handoff
  uint32_t kind;       // SM_KIND
  uint64_t sig;        // SM_SIG, the Darwin signal number
  uint64_t addr;       // SM_ADDR, si_addr
  uint64_t code;       // SM_CODE, si_code
  uint32_t trapno;     // SM_TRAPNO, from the exception state
  uint32_t err;        // SM_ERR, the page fault error code
  uint64_t fault;      // SM_FAULT, the faulting address
  uint64_t gsbase;     // SM_GSBASE, the guest FS base. The guest runs with it as GS base.
  uint64_t gsapplied;  // SM_GSAPPLIED, the GS base that the thread installed last
  uint32_t cold;       // SM_COLD, nonzero while the thread starts the guest
  uint32_t fpdirty;    // SM_FPDIRTY, nonzero when the resume must load fp
  uint32_t ninval;     // SM_NINVAL
  uint32_t pad0;
  struct gv_inval inval[GV_MAX_INVAL];  // SM_INVAL
  uint64_t tsdbase;    // SM_TSDBASE, the host GS base of the thread
  struct gv_ctx ctx;   // SM_CTX
  uint64_t hostsp;     // SM_HOSTSP, the host stack pointer for the exit path
  uint8_t fp[FP_SIZE] __attribute__((aligned(16)));  // SM_FP, FXSAVE image
};

// Command page. The template and every forked stub task own one.
struct gv_ctl {
  uint32_t seq;
  uint32_t ack;
  uint32_t cmd;
  int32_t result;
  uint64_t cookie;
  uint64_t arg;
  uint64_t arg2;
};

#define GV_LAYOUT_WORDS 14

struct gv_hello {
  uint64_t magic;
  uint32_t version;
  uint32_t kind;  // 0 for the template, 1 for a forked task
  uint64_t cookie;
  uint64_t pid;
  uint64_t ctl_addr;
  uint64_t page_size;
  uint64_t layout[GV_LAYOUT_WORDS];
};

#endif
#endif
