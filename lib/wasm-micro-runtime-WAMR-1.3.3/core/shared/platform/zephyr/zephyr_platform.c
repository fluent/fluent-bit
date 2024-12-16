/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

/* function pointers for executable memory management */
static exec_mem_alloc_func_t exec_mem_alloc_func = NULL;
static exec_mem_free_func_t exec_mem_free_func = NULL;

#if WASM_ENABLE_AOT != 0
#ifdef CONFIG_ARM_MPU
/**
 * This function will allow execute from sram region.
 * This is needed for AOT code because by default all soc will
 * disable the execute from SRAM.
 */
static void
disable_mpu_rasr_xn(void)
{
    uint32 index;
    /* Kept the max index as 8 (irrespective of soc) because the sram
       would most likely be set at index 2. */
    for (index = 0U; index < 8; index++) {
        MPU->RNR = index;
#ifdef MPU_RASR_XN_Msk
        if (MPU->RASR & MPU_RASR_XN_Msk) {
            MPU->RASR |= ~MPU_RASR_XN_Msk;
        }
#endif
    }
}
#endif /* end of CONFIG_ARM_MPU */
#endif

static int
_stdout_hook_iwasm(int c)
{
    printk("%c", (char)c);
    return 1;
}

int
os_thread_sys_init();

void
os_thread_sys_destroy();

int
bh_platform_init()
{
    extern void __stdout_hook_install(int (*hook)(int));
    /* Enable printf() in Zephyr */
    __stdout_hook_install(_stdout_hook_iwasm);

#if WASM_ENABLE_AOT != 0
#ifdef CONFIG_ARM_MPU
    /* Enable executable memory support */
    disable_mpu_rasr_xn();
#endif
#endif

    return os_thread_sys_init();
}

void
bh_platform_destroy()
{
    os_thread_sys_destroy();
}

void *
os_malloc(unsigned size)
{
    return malloc(size);
}

void *
os_realloc(void *ptr, unsigned size)
{
    return realloc(ptr, size);
}

void
os_free(void *ptr)
{
    free(ptr);
}

int
os_dumps_proc_mem_info(char *out, unsigned int size)
{
    return -1;
}

#if 0
struct out_context {
    int count;
};

typedef int (*out_func_t)(int c, void *ctx);

static int
char_out(int c, void *ctx)
{
    struct out_context *out_ctx = (struct out_context*)ctx;
    out_ctx->count++;
    return _stdout_hook_iwasm(c);
}

int
os_vprintf(const char *fmt, va_list ap)
{
#if 0
    struct out_context ctx = { 0 };
    cbvprintf(char_out, &ctx, fmt, ap);
    return ctx.count;
#else
    vprintk(fmt, ap);
    return 0;
#endif
}
#endif

int
os_printf(const char *format, ...)
{
    int ret = 0;
    va_list ap;

    va_start(ap, format);
#ifndef BH_VPRINTF
    ret += vprintf(format, ap);
#else
    ret += BH_VPRINTF(format, ap);
#endif
    va_end(ap);

    return ret;
}

int
os_vprintf(const char *format, va_list ap)
{
#ifndef BH_VPRINTF
    return vprintf(format, ap);
#else
    return BH_VPRINTF(format, ap);
#endif
}

#if KERNEL_VERSION_NUMBER <= 0x020400 /* version 2.4.0 */
void
abort(void)
{
    int i = 0;
    os_printf("%d\n", 1 / i);
}
#endif

#if KERNEL_VERSION_NUMBER <= 0x010E01 /* version 1.14.1 */
size_t
strspn(const char *s, const char *accept)
{
    os_printf("## unimplemented function %s called", __FUNCTION__);
    return 0;
}

size_t
strcspn(const char *s, const char *reject)
{
    os_printf("## unimplemented function %s called", __FUNCTION__);
    return 0;
}
#endif

void *
os_mmap(void *hint, size_t size, int prot, int flags, os_file_handle file)
{
    if ((uint64)size >= UINT32_MAX)
        return NULL;
    if (exec_mem_alloc_func)
        return exec_mem_alloc_func((uint32)size);
    else
        return BH_MALLOC(size);
}

void
os_munmap(void *addr, size_t size)
{
    if (exec_mem_free_func)
        exec_mem_free_func(addr);
    else
        BH_FREE(addr);
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    return 0;
}

void
os_dcache_flush()
{
#if defined(CONFIG_CPU_CORTEX_M7) && defined(CONFIG_ARM_MPU)
#if KERNEL_VERSION_NUMBER < 0x030300 /* version 3.3.0 */
    uint32 key;
    key = irq_lock();
    SCB_CleanDCache();
    irq_unlock(key);
#else
    sys_cache_data_flush_all();
#endif
#elif defined(CONFIG_SOC_CVF_EM7D) && defined(CONFIG_ARC_MPU) \
    && defined(CONFIG_CACHE_FLUSHING)
    __asm__ __volatile__("sync");
    z_arc_v2_aux_reg_write(_ARC_V2_DC_FLSH, BIT(0));
    __asm__ __volatile__("sync");
#endif
}

void
os_icache_flush(void *start, size_t len)
{
#if KERNEL_VERSION_NUMBER >= 0x030300 /* version 3.3.0 */
    sys_cache_instr_flush_range(start, len);
#endif
}

void
set_exec_mem_alloc_func(exec_mem_alloc_func_t alloc_func,
                        exec_mem_free_func_t free_func)
{
    exec_mem_alloc_func = alloc_func;
    exec_mem_free_func = free_func;
}
