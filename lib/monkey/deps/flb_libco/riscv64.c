/*
  libco.riscv64
  license: public domain
*/

#define LIBCO_C
#include "libco.h"
#include "settings.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__riscv_float_abi_double) || defined(__riscv_float_abi_single)
  #define LIBCO_RISCV64_HARD_FLOAT
#endif

typedef struct {
  uintptr_t ra;
  uintptr_t sp;
  uintptr_t s[12];
#ifdef LIBCO_RISCV64_HARD_FLOAT
  uint64_t fs[12];
  uintptr_t fcsr;
#endif
  void (*entrypoint)(void);
} co_context;

typedef char co_context_ra_offset[(offsetof(co_context, ra) == 0) ? 1 : -1];
typedef char co_context_sp_offset[(offsetof(co_context, sp) == 8) ? 1 : -1];
typedef char co_context_s_offset[(offsetof(co_context, s) == 16) ? 1 : -1];
#ifdef LIBCO_RISCV64_HARD_FLOAT
typedef char co_context_fs_offset[(offsetof(co_context, fs) == 112) ? 1 : -1];
typedef char co_context_fcsr_offset[(offsetof(co_context, fcsr) == 208) ? 1 : -1];
#endif

static thread_local co_context co_active_context;
static thread_local cothread_t co_active_handle;

#if defined(__riscv_float_abi_double)
  #define LIBCO_RISCV64_SAVE_FLOAT                                        \
    "  fsd fs0, 112(a1)\n"                                               \
    "  fsd fs1, 120(a1)\n"                                               \
    "  fsd fs2, 128(a1)\n"                                               \
    "  fsd fs3, 136(a1)\n"                                               \
    "  fsd fs4, 144(a1)\n"                                               \
    "  fsd fs5, 152(a1)\n"                                               \
    "  fsd fs6, 160(a1)\n"                                               \
    "  fsd fs7, 168(a1)\n"                                               \
    "  fsd fs8, 176(a1)\n"                                               \
    "  fsd fs9, 184(a1)\n"                                               \
    "  fsd fs10, 192(a1)\n"                                              \
    "  fsd fs11, 200(a1)\n"                                              \
    "  csrr t0, fcsr\n"                                                  \
    "  sd t0, 208(a1)\n"
  #define LIBCO_RISCV64_RESTORE_FLOAT                                     \
    "  fld fs0, 112(a0)\n"                                               \
    "  fld fs1, 120(a0)\n"                                               \
    "  fld fs2, 128(a0)\n"                                               \
    "  fld fs3, 136(a0)\n"                                               \
    "  fld fs4, 144(a0)\n"                                               \
    "  fld fs5, 152(a0)\n"                                               \
    "  fld fs6, 160(a0)\n"                                               \
    "  fld fs7, 168(a0)\n"                                               \
    "  fld fs8, 176(a0)\n"                                               \
    "  fld fs9, 184(a0)\n"                                               \
    "  fld fs10, 192(a0)\n"                                              \
    "  fld fs11, 200(a0)\n"                                              \
    "  ld t0, 208(a0)\n"                                                 \
    "  csrw fcsr, t0\n"
#elif defined(__riscv_float_abi_single)
  #define LIBCO_RISCV64_SAVE_FLOAT                                        \
    "  fsw fs0, 112(a1)\n"                                               \
    "  fsw fs1, 120(a1)\n"                                               \
    "  fsw fs2, 128(a1)\n"                                               \
    "  fsw fs3, 136(a1)\n"                                               \
    "  fsw fs4, 144(a1)\n"                                               \
    "  fsw fs5, 152(a1)\n"                                               \
    "  fsw fs6, 160(a1)\n"                                               \
    "  fsw fs7, 168(a1)\n"                                               \
    "  fsw fs8, 176(a1)\n"                                               \
    "  fsw fs9, 184(a1)\n"                                               \
    "  fsw fs10, 192(a1)\n"                                              \
    "  fsw fs11, 200(a1)\n"                                              \
    "  csrr t0, fcsr\n"                                                  \
    "  sd t0, 208(a1)\n"
  #define LIBCO_RISCV64_RESTORE_FLOAT                                     \
    "  flw fs0, 112(a0)\n"                                               \
    "  flw fs1, 120(a0)\n"                                               \
    "  flw fs2, 128(a0)\n"                                               \
    "  flw fs3, 136(a0)\n"                                               \
    "  flw fs4, 144(a0)\n"                                               \
    "  flw fs5, 152(a0)\n"                                               \
    "  flw fs6, 160(a0)\n"                                               \
    "  flw fs7, 168(a0)\n"                                               \
    "  flw fs8, 176(a0)\n"                                               \
    "  flw fs9, 184(a0)\n"                                               \
    "  flw fs10, 192(a0)\n"                                              \
    "  flw fs11, 200(a0)\n"                                              \
    "  ld t0, 208(a0)\n"                                                 \
    "  csrw fcsr, t0\n"
#else
  #define LIBCO_RISCV64_SAVE_FLOAT
  #define LIBCO_RISCV64_RESTORE_FLOAT
#endif

asm(
  ".text\n"
  ".p2align 2\n"
  ".globl co_switch_riscv64\n"
  ".type co_switch_riscv64, @function\n"
  "co_switch_riscv64:\n"
  "  sd ra, 0(a1)\n"
  "  sd sp, 8(a1)\n"
  "  sd s0, 16(a1)\n"
  "  sd s1, 24(a1)\n"
  "  sd s2, 32(a1)\n"
  "  sd s3, 40(a1)\n"
  "  sd s4, 48(a1)\n"
  "  sd s5, 56(a1)\n"
  "  sd s6, 64(a1)\n"
  "  sd s7, 72(a1)\n"
  "  sd s8, 80(a1)\n"
  "  sd s9, 88(a1)\n"
  "  sd s10, 96(a1)\n"
  "  sd s11, 104(a1)\n"
  LIBCO_RISCV64_SAVE_FLOAT
  "  ld ra, 0(a0)\n"
  "  ld sp, 8(a0)\n"
  "  ld s0, 16(a0)\n"
  "  ld s1, 24(a0)\n"
  "  ld s2, 32(a0)\n"
  "  ld s3, 40(a0)\n"
  "  ld s4, 48(a0)\n"
  "  ld s5, 56(a0)\n"
  "  ld s6, 64(a0)\n"
  "  ld s7, 72(a0)\n"
  "  ld s8, 80(a0)\n"
  "  ld s9, 88(a0)\n"
  "  ld s10, 96(a0)\n"
  "  ld s11, 104(a0)\n"
  LIBCO_RISCV64_RESTORE_FLOAT
  "  ret\n"
  ".size co_switch_riscv64, .-co_switch_riscv64\n"
  ".previous\n"
);

void co_switch_riscv64(cothread_t handle, cothread_t current);

static void co_entry_trampoline(void)
{
  co_context *context;

  context = (co_context *)co_active_handle;
  context->entrypoint();
  abort();
}

cothread_t co_active(void)
{
  if (!co_active_handle) {
    co_active_handle = &co_active_context;
  }

  return co_active_handle;
}

cothread_t co_create(unsigned int size, void (*entrypoint)(void),
                     size_t *out_size)
{
  size_t context_size;
  size_t stack_size;
  size_t total_size;
  co_context *context;

  context_size = (sizeof(co_context) + 15) & ~(size_t)15;

  if ((size_t)size > SIZE_MAX - 15) {
    return 0;
  }

  stack_size = ((size_t)size + 15) & ~(size_t)15;
  if (stack_size > SIZE_MAX - context_size) {
    return 0;
  }

  total_size = context_size + stack_size;
  context = (co_context *)malloc(total_size);
  if (!context) {
    return 0;
  }

  memset(context, 0, context_size);
  context->ra = (uintptr_t)co_entry_trampoline;
  context->sp = (uintptr_t)context + total_size;
  context->entrypoint = entrypoint;

  *out_size = total_size;
  return (cothread_t)context;
}

void co_delete(cothread_t handle)
{
  free(handle);
}

void co_switch(cothread_t handle)
{
  cothread_t previous_handle;

  previous_handle = co_active();
  co_active_handle = handle;
  co_switch_riscv64(handle, previous_handle);
}

#ifdef __cplusplus
}
#endif
