#define LIBCO_C
#include "libco.h"
#include "settings.h"

#include <stdint.h>
#ifdef LIBCO_MPROTECT
  #include <unistd.h>
  #include <sys/mman.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

static thread_local unsigned long co_active_buffer[64];
static thread_local cothread_t co_active_handle = 0;
static void (*co_swap)(cothread_t, cothread_t) = 0;

#ifdef LIBCO_MPROTECT
  alignas(4096)
#else
  section(text)
#endif
static const uint32_t co_swap_function[1024] = {
  0x910003f0,  /* mov x16,sp           */
  0xa9007830,  /* stp x16,x30,[x1]     */
  0xa9407810,  /* ldp x16,x30,[x0]     */
  0x9100021f,  /* mov sp,x16           */
  0xa9015033,  /* stp x19,x20,[x1, 16] */
  0xa9415013,  /* ldp x19,x20,[x0, 16] */
  0xa9025835,  /* stp x21,x22,[x1, 32] */
  0xa9425815,  /* ldp x21,x22,[x0, 32] */
  0xa9036037,  /* stp x23,x24,[x1, 48] */
  0xa9436017,  /* ldp x23,x24,[x0, 48] */
  0xa9046839,  /* stp x25,x26,[x1, 64] */
  0xa9446819,  /* ldp x25,x26,[x0, 64] */
  0xa905703b,  /* stp x27,x28,[x1, 80] */
  0xa945701b,  /* ldp x27,x28,[x0, 80] */
  0xf900303d,  /* str x29,    [x1, 96] */
  0xf940301d,  /* ldr x29,    [x0, 96] */
  0x6d072428,  /* stp d8, d9, [x1,112] */
  0x6d472408,  /* ldp d8, d9, [x0,112] */
  0x6d082c2a,  /* stp d10,d11,[x1,128] */
  0x6d482c0a,  /* ldp d10,d11,[x0,128] */
  0x6d09342c,  /* stp d12,d13,[x1,144] */
  0x6d49340c,  /* ldp d12,d13,[x0,144] */
  0x6d0a3c2e,  /* stp d14,d15,[x1,160] */
  0x6d4a3c0e,  /* ldp d14,d15,[x0,160] */
  0xd61f03c0,  /* br x30               */
};

static void co_init() {
  #ifdef LIBCO_MPROTECT
  unsigned long addr = (unsigned long)co_swap_function;
  unsigned long base = addr - (addr % sysconf(_SC_PAGESIZE));
  unsigned long size = (addr - base) + sizeof co_swap_function;
  mprotect((void*)base, size, PROT_READ | PROT_EXEC);
  #endif
}

cothread_t co_active() {
  if(!co_active_handle) co_active_handle = &co_active_buffer;
  return co_active_handle;
}

cothread_t co_derive(void* memory, unsigned int size, void (*entrypoint)(void)) {
  unsigned long* handle;
  if(!co_swap) {
    co_init();
    co_swap = (void (*)(cothread_t, cothread_t))co_swap_function;
  }
  if(!co_active_handle) co_active_handle = &co_active_buffer;

  if(handle = (unsigned long*)memory) {
    unsigned int offset = (size & ~15);
    unsigned long* p = (unsigned long*)((unsigned char*)handle + offset);
    handle[0]  = (unsigned long)p;           /* x16 (stack pointer) */
    handle[1]  = (unsigned long)entrypoint;  /* x30 (link register) */
    handle[12] = (unsigned long)p;           /* x29 (frame pointer) */
  }

  return handle;
}

cothread_t co_create(unsigned int size, void (*entrypoint)(void)) {
  void* memory = LIBCO_MALLOC(size);
  if(!memory) return (cothread_t)0;
  return co_derive(memory, size, entrypoint);
}

void co_delete(cothread_t handle) {
  LIBCO_FREE(handle);
}

void co_switch(cothread_t handle) {
  cothread_t co_previous_handle = co_active_handle;
  co_swap(co_active_handle = handle, co_previous_handle);
}

int co_serializable() {
  return 1;
}

#ifdef __cplusplus
}
#endif
