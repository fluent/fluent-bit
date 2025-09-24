/*
 * Copyright (c) 2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <platform_api_vmcore.h>
#include <platform_api_extension.h>

typedef struct os_malloc_list {
    void *real;
    void *used;
    rt_list_t node;
} os_malloc_list_t;

int
bh_platform_init(void)
{
    return 0;
}

void
bh_platform_destroy(void)
{}

void *
os_malloc(unsigned size)
{
    void *buf_origin;
    void *buf_fixed;
    rt_ubase_t *addr_field;

    buf_origin = rt_malloc(size + 8 + sizeof(rt_ubase_t));
    buf_fixed = buf_origin + sizeof(void *);
    if ((rt_ubase_t)buf_fixed & 0x7) {
        buf_fixed = (void *)((rt_ubase_t)(buf_fixed + 8) & (~7));
    }

    addr_field = buf_fixed - sizeof(rt_ubase_t);
    *addr_field = (rt_ubase_t)buf_origin;

    return buf_fixed;
}

void *
os_realloc(void *ptr, unsigned size)
{

    void *mem_origin;
    void *mem_new;
    void *mem_new_fixed;
    rt_ubase_t *addr_field;

    if (!ptr) {
        return RT_NULL;
    }

    addr_field = ptr - sizeof(rt_ubase_t);
    mem_origin = (void *)(*addr_field);
    mem_new = rt_realloc(mem_origin, size + 8 + sizeof(rt_ubase_t));

    if (mem_origin != mem_new) {
        mem_new_fixed = mem_new + sizeof(rt_ubase_t);
        if ((rt_ubase_t)mem_new_fixed & 0x7) {
            mem_new_fixed = (void *)((rt_ubase_t)(mem_new_fixed + 8) & (~7));
        }

        addr_field = mem_new_fixed - sizeof(rt_ubase_t);
        *addr_field = (rt_ubase_t)mem_new;

        return mem_new_fixed;
    }

    return ptr;
}

void
os_free(void *ptr)
{
    void *mem_origin;
    rt_ubase_t *addr_field;

    if (ptr) {
        addr_field = ptr - sizeof(rt_ubase_t);
        mem_origin = (void *)(*addr_field);

        rt_free(mem_origin);
    }
}

int
os_dumps_proc_mem_info(char *out, unsigned int size)
{
    return -1;
}

static char wamr_vprint_buf[RT_CONSOLEBUF_SIZE * 2];

int
os_printf(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    rt_size_t len =
        vsnprintf(wamr_vprint_buf, sizeof(wamr_vprint_buf) - 1, format, ap);
    wamr_vprint_buf[len] = 0x00;
    rt_kputs(wamr_vprint_buf);
    va_end(ap);
    return 0;
}

int
os_vprintf(const char *format, va_list ap)
{
    rt_size_t len =
        vsnprintf(wamr_vprint_buf, sizeof(wamr_vprint_buf) - 1, format, ap);
    wamr_vprint_buf[len] = 0;
    rt_kputs(wamr_vprint_buf);
    return 0;
}

uint64
os_time_get_boot_us(void)
{
    uint64 ret = rt_tick_get() * 1000;
    ret /= RT_TICK_PER_SECOND;
    return ret;
}

uint64
os_time_thread_cputime_us(void)
{
    /* FIXME if u know the right api */
    return os_time_get_boot_us();
}

void *
os_mmap(void *hint, size_t size, int prot, int flags, os_file_handle file)
{
    void *buf_origin;
    void *buf_fixed;
    rt_ubase_t *addr_field;

    buf_origin = rt_malloc(size + 8 + sizeof(rt_ubase_t));
    if (!buf_origin)
        return NULL;

    buf_fixed = buf_origin + sizeof(void *);
    if ((rt_ubase_t)buf_fixed & 0x7) {
        buf_fixed = (void *)((rt_ubase_t)(buf_fixed + 8) & (~7));
    }

    addr_field = buf_fixed - sizeof(rt_ubase_t);
    *addr_field = (rt_ubase_t)buf_origin;

    memset(buf_origin, 0, size + 8 + sizeof(rt_ubase_t));
    return buf_fixed;
}

void
os_munmap(void *addr, size_t size)
{
    void *mem_origin;
    rt_ubase_t *addr_field;

    if (addr) {
        addr_field = addr - sizeof(rt_ubase_t);
        mem_origin = (void *)(*addr_field);

        rt_free(mem_origin);
    }
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    return 0;
}

void
os_dcache_flush(void)
{}

void
os_icache_flush(void *start, size_t len)
{}

int
os_getpagesize(void)
{
    return 4096;
}

void *
os_mremap(void *in, size_t old_size, size_t new_size)
{
    return os_realloc(in, new_size);
}

__wasi_errno_t
os_clock_time_get(__wasi_clockid_t clock_id, __wasi_timestamp_t precision,
                  __wasi_timestamp_t *time)
{
    *time = rt_tick_get() * 1000ll * 1000ll;
    return 0;
}

__wasi_errno_t
os_clock_res_get(__wasi_clockid_t clock_id, __wasi_timestamp_t *resolution)
{
    return 0;
}
