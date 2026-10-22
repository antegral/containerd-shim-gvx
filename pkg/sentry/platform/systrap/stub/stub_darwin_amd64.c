// macOS amd64 systrap stub. Rosetta 2 translates it, and it also translates
// the guest code that runs in its threads. The stub links libSystem for dyld,
// fork, pthread_create, sigaction and sandbox_init. Guest threads run only the
// signal handler below and raw system calls, because a guest thread uses GS for
// the guest TLS and libSystem needs GS for its own thread data.

#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
#include <pthread.h>
#include <servers/bootstrap.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include "gvx_stub_amd64.h"

extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
                                        const char *const parameters[],
                                        char **errorbuf);

_Static_assert(offsetof(struct gv_sysmsg, magic) == SM_MAGIC, "magic");
_Static_assert(offsetof(struct gv_sysmsg, state) == SM_STATE, "state");
_Static_assert(offsetof(struct gv_sysmsg, kind) == SM_KIND, "kind");
_Static_assert(offsetof(struct gv_sysmsg, sig) == SM_SIG, "sig");
_Static_assert(offsetof(struct gv_sysmsg, addr) == SM_ADDR, "addr");
_Static_assert(offsetof(struct gv_sysmsg, code) == SM_CODE, "code");
_Static_assert(offsetof(struct gv_sysmsg, trapno) == SM_TRAPNO, "trapno");
_Static_assert(offsetof(struct gv_sysmsg, err) == SM_ERR, "err");
_Static_assert(offsetof(struct gv_sysmsg, fault) == SM_FAULT, "fault");
_Static_assert(offsetof(struct gv_sysmsg, gsbase) == SM_GSBASE, "gsbase");
_Static_assert(offsetof(struct gv_sysmsg, gsapplied) == SM_GSAPPLIED, "gsapplied");
_Static_assert(offsetof(struct gv_sysmsg, cold) == SM_COLD, "cold");
_Static_assert(offsetof(struct gv_sysmsg, fpdirty) == SM_FPDIRTY, "fpdirty");
_Static_assert(offsetof(struct gv_sysmsg, ninval) == SM_NINVAL, "ninval");
_Static_assert(offsetof(struct gv_sysmsg, inval) == SM_INVAL, "inval");
_Static_assert(offsetof(struct gv_sysmsg, tsdbase) == SM_TSDBASE, "tsdbase");
_Static_assert(offsetof(struct gv_sysmsg, ctx) == SM_CTX, "ctx");
_Static_assert(offsetof(struct gv_sysmsg, hostsp) == SM_HOSTSP, "hostsp");
_Static_assert(offsetof(struct gv_sysmsg, fp) == SM_FP, "fp");
_Static_assert(sizeof(struct gv_ctx) == CTX_SIZE, "ctx size");
_Static_assert(sizeof(struct gv_sysmsg) <= GV_SYSMSG_SIZE, "sysmsg size");
_Static_assert(sizeof(((_STRUCT_MCONTEXT64 *)0)->__ss) == CTX_SIZE, "mcontext ss");
_Static_assert(offsetof(_STRUCT_MCONTEXT64, __fs) == 16 + CTX_SIZE, "mcontext fs");

// Raw BSD system calls. libSystem wrappers would write errno through GS,
// and a guest thread has the guest TLS in GS. Rosetta runs these `syscall`
// instructions as host system calls because the number carries the BSD class.
static inline long raw_syscall4(long nr, long a0, long a1, long a2, long a3) {
  long ret;
  register long r10 __asm__("r10") = a3;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(0x2000000L + nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                   : "rcx", "r11", "memory", "cc");
  return ret;
}

enum {
  SYS_exit = 1,
  SYS_mprotect = 74,
  SYS_ulock_wait = 515,
  SYS_ulock_wake = 516,
  UL_COMPARE_AND_WAIT_SHARED = 3,
  ULF_WAKE_ALL = 0x100,
};

// Rosetta runs the machdep call that installs the GS base of the thread.
static inline void set_gs_base(uint64_t base) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(0x3000003L), "D"(base)
                   : "rcx", "r11", "memory", "cc");
}

static inline void ulock_wake_all(uint32_t *addr) {
  raw_syscall4(SYS_ulock_wake, UL_COMPARE_AND_WAIT_SHARED | ULF_WAKE_ALL, (long)addr, 0, 0);
}

static inline void ulock_wait(uint32_t *addr, uint32_t expected, uint32_t micros) {
  raw_syscall4(SYS_ulock_wait, UL_COMPARE_AND_WAIT_SHARED, (long)addr, expected, micros);
}

// Word copies through volatile pointers stop the compiler from calling memcpy.
// The handler must not call libSystem, because a lazy dyld binding would use GS.
static void copy_words(volatile uint64_t *dst, const volatile uint64_t *src, size_t bytes) {
  for (size_t i = 0; i < bytes / 8; i++) {
    dst[i] = src[i];
  }
}

static struct gv_sysmsg *sysmsg_of_sp(void) {
  uint64_t sp;
  __asm__ volatile("mov %%rsp, %0" : "=r"(sp));
  return (struct gv_sysmsg *)((sp - 1) & ~(uint64_t)(GV_THREAD_SPAN - 1));
}

// gv_park publishes the trap reason, wakes the Sentry and blocks until the
// Sentry resumes the thread. It returns the resume state.
static uint32_t gv_park(struct gv_sysmsg *sm, uint32_t kind) {
  sm->kind = kind;
  __atomic_store_n(&sm->state, GV_ST_TRAPPED, __ATOMIC_RELEASE);
  ulock_wake_all(&sm->state);
  for (;;) {
    uint32_t s = __atomic_load_n(&sm->state, __ATOMIC_ACQUIRE);
    if (s == GV_ST_RUN || s == GV_ST_COLD || s == GV_ST_EXIT) {
      return s;
    }
    ulock_wait(&sm->state, s, 0);
  }
}

extern void gv_thread_unwind(void);
extern void *gv_thread_entry(void *);

// The Sentry asks the Rosetta runtime to drop its translation of a page by
// changing the protection of the page inside this task. A change that the
// Sentry makes from outside leaves the stale translation in place.
static void run_invalidations(struct gv_sysmsg *sm) {
  uint32_t n = sm->ninval;
  if (n > GV_MAX_INVAL) {
    n = GV_MAX_INVAL;
  }
  for (uint32_t i = 0; i < n; i++) {
    raw_syscall4(SYS_mprotect, sm->inval[i].addr, sm->inval[i].len, sm->inval[i].tmp_prot, 0);
    raw_syscall4(SYS_mprotect, sm->inval[i].addr, sm->inval[i].len, sm->inval[i].final_prot, 0);
  }
  sm->ninval = 0;
}

static void load_context(struct gv_sysmsg *sm, _STRUCT_MCONTEXT64 *mc, int fp) {
  // The segment selectors of the guest are not its own, so they keep the values
  // that the kernel gave: cs, fs and gs.
  copy_words((volatile uint64_t *)&mc->__ss, (const volatile uint64_t *)&sm->ctx, offsetof(struct gv_ctx, cs));
  if (fp) {
    copy_words((volatile uint64_t *)((char *)&mc->__fs + 8), (const volatile uint64_t *)sm->fp, FP_SIZE);
    sm->fpdirty = 0;
  }
  uint64_t want = sm->gsbase;
  if (want != sm->gsapplied) {
    set_gs_base(want);
    sm->gsapplied = want;
  }
}

// gv_sighandler runs on the per-thread alternate stack for every signal that
// guest code raises. It copies the frame to the sysmsg, parks, and writes the
// Sentry state back before it returns through sigreturn.
void gv_sighandler(int sig, siginfo_t *info, void *vuc) {
  ucontext_t *uc = vuc;
  _STRUCT_MCONTEXT64 *mc = uc->uc_mcontext;
  struct gv_sysmsg *sm = sysmsg_of_sp();
  if (sm->magic != GV_MAGIC) {
    raw_syscall4(SYS_exit, 139, 0, 0, 0);
  }
  if (sm->cold != 0) {
    // The thread raised this trap itself to enter the guest. Load the context.
    sm->cold = 0;
    load_context(sm, mc, 1);
    return;
  }
  copy_words((volatile uint64_t *)&sm->ctx, (const volatile uint64_t *)&mc->__ss, sizeof(struct gv_ctx));
  copy_words((volatile uint64_t *)sm->fp, (const volatile uint64_t *)((char *)&mc->__fs + 8), FP_SIZE);
  sm->trapno = mc->__es.__trapno;
  sm->err = mc->__es.__err;
  sm->fault = mc->__es.__faultvaddr;
  sm->sig = (uint64_t)sig;
  sm->addr = (uint64_t)info->si_addr;
  sm->code = (uint64_t)(int64_t)info->si_code;
  uint32_t st = gv_park(sm, sig == SIGUSR2 ? GV_KIND_INTERRUPT : GV_KIND_SIGNAL);
  if (st == GV_ST_EXIT) {
    // Leave the guest context: return into the epilogue of gv_thread_entry.
    set_gs_base(sm->tsdbase);
    sm->gsapplied = sm->tsdbase;
    mc->__ss.__rip = (uint64_t)&gv_thread_unwind;
    mc->__ss.__rsp = sm->hostsp;
    return;
  }
  run_invalidations(sm);
  load_context(sm, mc, sm->fpdirty != 0);
}

// ----- guest thread --------------------------------------------------------

struct thread_slot {
  pthread_t thread;
  struct gv_sysmsg *sm;
  uint64_t entry_sp;
  int live;
};

static struct thread_slot slots[GV_MAX_THREADS];

// host_gs_base returns the GS base that libpthread installed for the calling
// thread. Rosetta offers no call that reads it. The first slot of the thread
// specific data array holds the pthread_self pointer, and that slot lies at the
// GS base, so a scan of the pthread structure for its own address finds the base.
static uint64_t host_gs_base(void) {
  uint64_t self;
  __asm__ volatile("movq %%gs:0, %0" : "=r"(self));
  const volatile uint64_t *words = (const volatile uint64_t *)self;
  for (size_t i = 1; i < 128; i++) {
    if (words[i] == self) {
      return self + 8 * i;
    }
  }
  return 0;
}

// gv_thread_run is the C body of a guest thread. The assembly entry calls it
// with the slot and the stack frame that the exit path of the handler restores.
void *gv_thread_run(struct thread_slot *slot, uint64_t frame) {
  struct gv_sysmsg *sm = slot->sm;
  sm->hostsp = frame;
  uint64_t tsd = host_gs_base();
  if (tsd == 0) {
    return NULL;
  }
  sm->tsdbase = tsd;
  sm->gsapplied = tsd;
  stack_t ss;
  memset(&ss, 0, sizeof ss);
  ss.ss_sp = (char *)sm + GV_ALTSTACK_BASE;
  ss.ss_size = GV_ALTSTACK_TOP - GV_ALTSTACK_BASE;
  if (sigaltstack(&ss, NULL) != 0) {
    return NULL;
  }
  uint32_t st = gv_park(sm, GV_KIND_START);
  if (st == GV_ST_EXIT) {
    return NULL;
  }
  sm->cold = 1;
  __asm__ volatile("int3");
  return NULL;
}

static int start_thread(uint64_t span, uint64_t index) {
  if (index >= GV_MAX_THREADS || slots[index].live) {
    return -1;
  }
  struct thread_slot *slot = &slots[index];
  slot->sm = (struct gv_sysmsg *)span;
  pthread_attr_t attr;
  if (pthread_attr_init(&attr) != 0) {
    return -2;
  }
  int rc = pthread_attr_setstack(&attr, (void *)(span + GV_STACK_BASE), GV_STACK_TOP - GV_STACK_BASE);
  if (rc == 0) {
    rc = pthread_create(&slot->thread, &attr, gv_thread_entry, slot);
  }
  pthread_attr_destroy(&attr);
  if (rc != 0) {
    return -1000 - rc;
  }
  slot->live = 1;
  return 0;
}

static int join_thread(uint64_t index) {
  if (index >= GV_MAX_THREADS || !slots[index].live) {
    return -1;
  }
  struct thread_slot *slot = &slots[index];
  __atomic_store_n(&slot->sm->state, GV_ST_EXIT, __ATOMIC_RELEASE);
  ulock_wake_all(&slot->sm->state);
  if (pthread_join(slot->thread, NULL) != 0) {
    return -2;
  }
  slot->live = 0;
  return 0;
}

static int kick_thread(uint64_t index) {
  if (index >= GV_MAX_THREADS || !slots[index].live) {
    return -1;
  }
  return pthread_kill(slots[index].thread, SIGUSR2) == 0 ? 0 : -2;
}

// ----- control channel -----------------------------------------------------

// The profile of every forked stub task. The kernel allows one sandbox_init per
// process lineage, so the template runs without a profile and each forked task
// applies this one as its first and only profile. The allow list holds the
// system calls that the stub, libpthread and the Rosetta runtime need. The
// Rosetta runtime needs mprotect to track self-modifying code.
#ifndef GV_ALLOW_UNIX
#define GV_ALLOW_UNIX "1 53 74 515 516"
#endif
#ifndef GV_ALLOW_MACH
#define GV_ALLOW_MACH "MSC_mach_msg_trap MSC_mach_msg2_trap MSC__kernelrpc_mach_port_deallocate_trap"
#endif
#ifndef GV_DENY_ACTION
#define GV_DENY_ACTION " (with send-signal SIGKILL)"
#endif
#ifdef GV_PROFILE_OVERRIDE
static const char sandbox_child[] = GV_PROFILE_OVERRIDE;
#else
static const char sandbox_child[] =
    "(version 1)\n"
    "(deny default)\n"
    "(deny syscall-unix" GV_DENY_ACTION ")\n"
    "(allow syscall-unix (syscall-number " GV_ALLOW_UNIX "))\n"
    "(deny syscall-mach" GV_DENY_ACTION ")\n"
    "(allow syscall-mach (machtrap-number " GV_ALLOW_MACH "))\n"
    "(deny syscall-mig" GV_DENY_ACTION ")\n";
#endif

typedef struct {
  mach_msg_header_t h;
  mach_msg_body_t b;
  mach_msg_port_descriptor_t task;
  mach_msg_port_descriptor_t reply;
  mach_msg_port_descriptor_t entry;
  struct gv_hello hello;
  mach_msg_trailer_t trailer;
} hello_msg_t;

typedef struct {
  mach_msg_header_t h;
  mach_msg_body_t b;
  mach_msg_port_descriptor_t port;
  mach_msg_trailer_t trailer;
} port_msg_t;

static struct gv_ctl *ctl;
static mach_port_t ctl_entry;
static mach_port_t sentry_port;

// make_ctl creates the command page as a named memory entry. A plain shared
// anonymous mapping that the Sentry remaps does not share its wait queue with the
// original mapping under Rosetta, so a wake from the Sentry never reaches a thread
// that waits on its own mapping. Both tasks map the same entry, and then they do.
static int make_ctl(int inherit_none) {
  memory_object_size_t size = GV_BLOCK_SIZE;
  if (mach_make_memory_entry_64(mach_task_self(), &size, 0,
                                MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE, &ctl_entry,
                                MACH_PORT_NULL) != KERN_SUCCESS) {
    return -1;
  }
  mach_vm_address_t addr = 0;
  if (mach_vm_map(mach_task_self(), &addr, size, 0, VM_FLAGS_ANYWHERE, ctl_entry, 0, FALSE,
                  VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
                  inherit_none ? VM_INHERIT_NONE : VM_INHERIT_SHARE) != KERN_SUCCESS) {
    return -1;
  }
  ctl = (struct gv_ctl *)addr;
  return 0;
}

static int send_hello(mach_port_t dest, uint32_t kind, uint64_t cookie, mach_port_t reply) {
  hello_msg_t m;
  memset(&m, 0, sizeof m);
  m.h.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  m.h.msgh_size = sizeof m - sizeof m.trailer;
  m.h.msgh_remote_port = dest;
  m.h.msgh_id = 77;
  m.b.msgh_descriptor_count = 3;
  m.task.name = mach_task_self();
  m.task.disposition = MACH_MSG_TYPE_COPY_SEND;
  m.task.type = MACH_MSG_PORT_DESCRIPTOR;
  m.reply.name = reply;
  m.reply.disposition = MACH_MSG_TYPE_MAKE_SEND;
  m.reply.type = MACH_MSG_PORT_DESCRIPTOR;
  m.entry.name = ctl_entry;
  m.entry.disposition = MACH_MSG_TYPE_COPY_SEND;
  m.entry.type = MACH_MSG_PORT_DESCRIPTOR;
  m.hello.magic = GV_HELLO_MAGIC;
  m.hello.version = GV_PROTOCOL_VERSION;
  m.hello.kind = kind;
  m.hello.cookie = cookie;
  m.hello.pid = (uint64_t)getpid();
  m.hello.ctl_addr = (uint64_t)ctl;
  m.hello.page_size = (uint64_t)getpagesize();
  uint64_t layout[GV_LAYOUT_WORDS] = {
      GV_SYSMSG_SIZE, SM_STATE, SM_KIND, SM_GSBASE, SM_COLD, SM_INVAL, SM_CTX,
      SM_FP, CTX_SIZE, FP_SIZE, GV_STACK_TOP, GV_ALTSTACK_TOP, sizeof(struct gv_ctl), SM_TSDBASE};
  memcpy(m.hello.layout, layout, sizeof layout);
  return mach_msg(&m.h, MACH_SEND_MSG, m.h.msgh_size, 0, 0, MACH_MSG_TIMEOUT_NONE, 0);
}

// fetch_sentry_port reads the send right to the Sentry from the task's
// resource-exception registration. Mach port names do not survive fork, but
// the kernel copies the registration into the child, so the child fetches
// its own right.
static int fetch_sentry_port(void) {
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_msg_type_number_t count = EXC_TYPES_COUNT;
  mach_port_t ports[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
  if (task_get_exception_ports(mach_task_self(), EXC_MASK_RESOURCE, masks, &count, ports,
                               behaviors, flavors) != KERN_SUCCESS ||
      count < 1 || !MACH_PORT_VALID(ports[0])) {
    return -1;
  }
  sentry_port = ports[0];
  return 0;
}

static int install_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = gv_sighandler;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
  sigfillset(&sa.sa_mask);
  static const int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE, SIGEMT, SIGSYS, SIGUSR2};
  for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
    if (sigaction(sigs[i], &sa, NULL) != 0) {
      return -1;
    }
  }
  return 0;
}

// The control thread has no guest context. A fault on it reaches the handler
// with a stack that carries no sysmsg magic, and the handler ends the task.
// The Mach-O segment alignment is 4KB, so the span comes from mmap and aligns by hand.
static int install_control_altstack(void) {
  char *raw = mmap(NULL, 2 * GV_THREAD_SPAN, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  if (raw == MAP_FAILED) {
    return -1;
  }
  uintptr_t span = ((uintptr_t)raw + GV_THREAD_SPAN - 1) & ~(uintptr_t)(GV_THREAD_SPAN - 1);
  stack_t ss;
  memset(&ss, 0, sizeof ss);
  ss.ss_sp = (void *)(span + GV_ALTSTACK_BASE);
  ss.ss_size = GV_ALTSTACK_TOP - GV_ALTSTACK_BASE;
  return sigaltstack(&ss, NULL);
}

static int apply_sandbox(const char *profile) {
  char *err = NULL;
  return sandbox_init_with_parameters(profile, 0, NULL, &err);
}

static void ack(uint32_t seq) {
  __atomic_store_n(&ctl->ack, seq, __ATOMIC_RELEASE);
  ulock_wake_all(&ctl->ack);
}

// serve_forked runs the command loop of a forked stub task. Its commands
// create, kick and join guest threads.
static void serve_forked(void) {
  uint32_t last = 0;
  for (;;) {
    uint32_t seq = __atomic_load_n(&ctl->seq, __ATOMIC_ACQUIRE);
    if (seq == last) {
      ulock_wait(&ctl->seq, seq, 0);
      continue;
    }
    last = seq;
    switch (ctl->cmd) {
      case GV_CMD_THREAD:
        ctl->result = start_thread(ctl->arg, ctl->arg2);
        break;
      case GV_CMD_KICK:
        ctl->result = kick_thread(ctl->arg2);
        break;
      case GV_CMD_JOIN:
        ctl->result = join_thread(ctl->arg2);
        break;
      case GV_CMD_EXIT:
        _exit(0);
      default:
        ctl->result = -100;
    }
    ack(seq);
  }
}

// child_main runs in the forked process. It drops the channel to the Sentry
// as soon as the hello message is out.
static void child_main(uint64_t cookie) {
  if (fetch_sentry_port() != 0) {
    _exit(42);
  }
  task_set_exception_ports(mach_task_self(), EXC_MASK_RESOURCE, MACH_PORT_NULL,
                           EXCEPTION_DEFAULT, 0);
  // The template mapped its command page without inheritance, so the child maps its own.
  if (make_ctl(1) != 0 || install_control_altstack() != 0) {
    _exit(43);
  }
#ifndef GV_NO_SANDBOX
  if (apply_sandbox(sandbox_child) != 0) {
    _exit(40);
  }
#endif
  if (send_hello(sentry_port, 1, cookie, MACH_PORT_NULL) != KERN_SUCCESS) {
    _exit(41);
  }
  mach_port_deallocate(mach_task_self(), sentry_port);
  serve_forked();
}

static int read_rendezvous_name(char *buf, size_t n) {
  size_t len = 0;
  while (len + 1 < n) {
    ssize_t r = read(0, buf + len, 1);
    if (r <= 0) {
      return -1;
    }
    if (buf[len] == '\n') {
      break;
    }
    len++;
  }
  buf[len] = 0;
  close(0);
  return len > 0 ? 0 : -1;
}

// rendezvous reaches the Sentry through the bootstrap name on stdin, hands it
// the task port and receives the long-lived port of the Sentry in return.
static int rendezvous(void) {
  char name[128];
  if (read_rendezvous_name(name, sizeof name) != 0) {
    return 10;
  }
  mach_port_t rendezvous_port = MACH_PORT_NULL;
  if (bootstrap_look_up(bootstrap_port, name, &rendezvous_port) != KERN_SUCCESS) {
    return 11;
  }
  mach_port_t reply = MACH_PORT_NULL;
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply) != KERN_SUCCESS) {
    return 12;
  }
  if (send_hello(rendezvous_port, 0, 0, reply) != KERN_SUCCESS) {
    return 13;
  }
  mach_port_deallocate(mach_task_self(), rendezvous_port);
  port_msg_t m;
  memset(&m, 0, sizeof m);
  if (mach_msg(&m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof m, reply, 20000, MACH_PORT_NULL) !=
          KERN_SUCCESS ||
      m.b.msgh_descriptor_count != 1 || !MACH_PORT_VALID(m.port.name)) {
    return 14;
  }
  sentry_port = m.port.name;
  mach_port_mod_refs(mach_task_self(), reply, MACH_PORT_RIGHT_RECEIVE, -1);
  // The registration is the one object that survives fork and names the Sentry.
  if (task_set_exception_ports(mach_task_self(), EXC_MASK_RESOURCE, sentry_port,
                               EXCEPTION_DEFAULT, THREAD_STATE_NONE) != KERN_SUCCESS) {
    return 15;
  }
  mach_port_deallocate(mach_task_self(), sentry_port);
  return 0;
}

int main(void) {
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  if (install_handlers() != 0) {
    return 16;
  }
  // The control page is shared with the Sentry. Forked children must not
  // inherit it, because guest code could otherwise send commands to the template.
  if (make_ctl(1) != 0) {
    return 17;
  }
  int rc = rendezvous();
  if (rc != 0) {
    return rc;
  }
  uint32_t last = 0;
  const pid_t sentry_pid = getppid();
  for (;;) {
    uint32_t seq = __atomic_load_n(&ctl->seq, __ATOMIC_ACQUIRE);
    if (seq == last) {
      // A bounded wait doubles as the watchdog. When the Sentry dies, launchd
      // adopts the template. The template then ends its whole process group,
      // which holds every stub task that it forked.
      if (getppid() != sentry_pid) {
        killpg(getpgrp(), SIGKILL);
        _exit(0);
      }
      ulock_wait(&ctl->seq, seq, 500000);
      continue;
    }
    last = seq;
    switch (ctl->cmd) {
      case GV_CMD_FORK: {
        uint64_t cookie = ctl->cookie;
        pid_t pid = fork();
        if (pid == 0) {
          child_main(cookie);
        }
        ctl->result = pid < 0 ? -1 : (int32_t)pid;
        break;
      }
      case GV_CMD_KILL: {
        // The template is the parent of every guest-hosting stub, so it is the
        // one process that may signal them after the Sentry locks itself down.
        pid_t victim = (pid_t)ctl->arg;
        ctl->result = victim > 1 && kill(victim, SIGKILL) == 0 ? 0 : -1;
        break;
      }
      case GV_CMD_EXIT:
        _exit(0);
      default:
        ctl->result = -2;
    }
    ack(seq);
  }
}
