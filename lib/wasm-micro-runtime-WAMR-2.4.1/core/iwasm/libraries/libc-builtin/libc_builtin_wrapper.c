/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_common.h"
#include "bh_log.h"
#include "wasm_export.h"
#include "../interpreter/wasm.h"

#if defined(_WIN32) || defined(_WIN32_)
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

void
wasm_runtime_set_exception(wasm_module_inst_t module, const char *exception);

uint64
wasm_runtime_module_realloc(wasm_module_inst_t module, uint64 ptr, uint64 size,
                            void **p_native_addr);

/* clang-format off */
#define get_module_inst(exec_env) \
    wasm_runtime_get_module_inst(exec_env)

#define validate_app_addr(offset, size) \
    wasm_runtime_validate_app_addr(module_inst, offset, size)

#define validate_app_str_addr(offset) \
    wasm_runtime_validate_app_str_addr(module_inst, offset)

#define validate_native_addr(addr, size) \
    wasm_runtime_validate_native_addr(module_inst, addr, size)

#define addr_app_to_native(offset) \
    wasm_runtime_addr_app_to_native(module_inst, offset)

#define addr_native_to_app(ptr) \
    wasm_runtime_addr_native_to_app(module_inst, ptr)

#define module_malloc(size, p_native_addr) \
    wasm_runtime_module_malloc(module_inst, size, p_native_addr)

#define module_free(offset) \
    wasm_runtime_module_free(module_inst, offset)
/* clang-format on */

typedef int (*out_func_t)(int c, void *ctx);

typedef char *_va_list;
#define _INTSIZEOF(n) (((uint32)sizeof(n) + 3) & (uint32)~3)
#define _va_arg(ap, t) (*(t *)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)))

#define CHECK_VA_ARG(ap, t)                                  \
    do {                                                     \
        if ((uint8 *)ap + _INTSIZEOF(t) > native_end_addr) { \
            if (fmt_buf != temp_fmt) {                       \
                wasm_runtime_free(fmt_buf);                  \
            }                                                \
            goto fail;                                       \
        }                                                    \
    } while (0)

/* clang-format off */
#define PREPARE_TEMP_FORMAT()                                \
    char temp_fmt[32], *s, *fmt_buf = temp_fmt;              \
    uint32 fmt_buf_len = (uint32)sizeof(temp_fmt);           \
    int32 n;                                                 \
                                                             \
    /* additional 2 bytes: one is the format char,           \
       the other is `\0` */                                  \
    if ((uint32)(fmt - fmt_start_addr + 2) >= fmt_buf_len) { \
        bh_assert((uint32)(fmt - fmt_start_addr) <=          \
                  UINT32_MAX - 2);                           \
        fmt_buf_len = (uint32)(fmt - fmt_start_addr + 2);    \
        if (!(fmt_buf = wasm_runtime_malloc(fmt_buf_len))) { \
            print_err(out, ctx);                             \
            break;                                           \
        }                                                    \
    }                                                        \
                                                             \
    memset(fmt_buf, 0, fmt_buf_len);                         \
    bh_memcpy_s(fmt_buf, fmt_buf_len, fmt_start_addr,        \
                (uint32)(fmt - fmt_start_addr + 1));
/* clang-format on */

#define OUTPUT_TEMP_FORMAT()            \
    do {                                \
        if (n > 0) {                    \
            s = buf;                    \
            while (*s)                  \
                out((int)(*s++), ctx);  \
        }                               \
                                        \
        if (fmt_buf != temp_fmt) {      \
            wasm_runtime_free(fmt_buf); \
        }                               \
    } while (0)

static void
print_err(out_func_t out, void *ctx)
{
    out('E', ctx);
    out('R', ctx);
    out('R', ctx);
}

static bool
_vprintf_wa(out_func_t out, void *ctx, const char *fmt, _va_list ap,
            wasm_module_inst_t module_inst)
{
    int might_format = 0; /* 1 if encountered a '%' */
    int long_ctr = 0;
    uint8 *native_end_addr;
    const char *fmt_start_addr = NULL;

    if (!wasm_runtime_get_native_addr_range(module_inst, (uint8 *)ap, NULL,
                                            &native_end_addr))
        goto fail;

    /* fmt has already been adjusted if needed */

    while (*fmt) {
        if (!might_format) {
            if (*fmt != '%') {
                out((int)*fmt, ctx);
            }
            else {
                might_format = 1;
                long_ctr = 0;
                fmt_start_addr = fmt;
            }
        }
        else {
            switch (*fmt) {
                case '.':
                case '+':
                case '-':
                case ' ':
                case '#':
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    goto still_might_format;

                case 't': /* ptrdiff_t */
                case 'z': /* size_t (32bit on wasm) */
                    long_ctr = 1;
                    goto still_might_format;

                case 'j':
                    /* intmax_t/uintmax_t */
                    long_ctr = 2;
                    goto still_might_format;

                case 'l':
                    long_ctr++;
                    /* Fall through */
                case 'h':
                    /* FIXME: do nothing for these modifiers */
                    goto still_might_format;

                case 'o':
                case 'd':
                case 'i':
                case 'u':
                case 'p':
                case 'x':
                case 'X':
                case 'c':
                {
                    char buf[64];
                    PREPARE_TEMP_FORMAT();

                    if (long_ctr < 2) {
                        int32 d;

                        CHECK_VA_ARG(ap, uint32);
                        d = _va_arg(ap, int32);

                        if (long_ctr == 1) {
                            uint32 fmt_end_idx = (uint32)(fmt - fmt_start_addr);

                            if (fmt_buf[fmt_end_idx - 1] == 'l'
                                || fmt_buf[fmt_end_idx - 1] == 'z'
                                || fmt_buf[fmt_end_idx - 1] == 't') {
                                /* The %ld, %zd and %td should be treated as
                                 * 32bit integer in wasm */
                                fmt_buf[fmt_end_idx - 1] = fmt_buf[fmt_end_idx];
                                fmt_buf[fmt_end_idx] = '\0';
                            }
                        }

                        n = snprintf(buf, sizeof(buf), fmt_buf, d);
                    }
                    else {
                        int64 lld;

                        /* Make 8-byte aligned */
                        ap = (_va_list)(((uintptr_t)ap + 7) & ~(uintptr_t)7);
                        CHECK_VA_ARG(ap, uint64);
                        lld = _va_arg(ap, int64);
                        n = snprintf(buf, sizeof(buf), fmt_buf, lld);
                    }

                    OUTPUT_TEMP_FORMAT();
                    break;
                }

                case 's':
                {
                    char buf_tmp[128], *buf = buf_tmp;
                    char *start;
                    uint32 s_offset, str_len, buf_len;

                    PREPARE_TEMP_FORMAT();

                    CHECK_VA_ARG(ap, int32);
                    s_offset = _va_arg(ap, uint32);

                    if (!validate_app_str_addr(s_offset)) {
                        if (fmt_buf != temp_fmt) {
                            wasm_runtime_free(fmt_buf);
                        }
                        return false;
                    }

                    s = start = addr_app_to_native((uint64)s_offset);

                    str_len = (uint32)strlen(start);
                    if (str_len >= UINT32_MAX - 64) {
                        print_err(out, ctx);
                        if (fmt_buf != temp_fmt) {
                            wasm_runtime_free(fmt_buf);
                        }
                        break;
                    }

                    /* reserve 64 more bytes as there may be width description
                     * in the fmt */
                    buf_len = str_len + 64;

                    if (buf_len > (uint32)sizeof(buf_tmp)) {
                        if (!(buf = wasm_runtime_malloc(buf_len))) {
                            print_err(out, ctx);
                            if (fmt_buf != temp_fmt) {
                                wasm_runtime_free(fmt_buf);
                            }
                            break;
                        }
                    }

                    n = snprintf(buf, buf_len, fmt_buf,
                                 (s_offset == 0 && str_len == 0) ? NULL
                                                                 : start);

                    OUTPUT_TEMP_FORMAT();

                    if (buf != buf_tmp) {
                        wasm_runtime_free(buf);
                    }

                    break;
                }

                case '%':
                {
                    out((int)'%', ctx);
                    break;
                }

                case 'e':
                case 'E':
                case 'g':
                case 'G':
                case 'f':
                case 'F':
                {
                    float64 f64;
                    char buf[64];
                    PREPARE_TEMP_FORMAT();

                    /* Make 8-byte aligned */
                    ap = (_va_list)(((uintptr_t)ap + 7) & ~(uintptr_t)7);
                    CHECK_VA_ARG(ap, float64);
                    f64 = _va_arg(ap, float64);
                    n = snprintf(buf, sizeof(buf), fmt_buf, f64);

                    OUTPUT_TEMP_FORMAT();
                    break;
                }

                case 'n':
                    /* print nothing */
                    break;

                default:
                    out((int)'%', ctx);
                    out((int)*fmt, ctx);
                    break;
            }

            might_format = 0;
        }

    still_might_format:
        ++fmt;
    }
    return true;

fail:
    wasm_runtime_set_exception(module_inst, "out of bounds memory access");
    return false;
}

#ifndef BUILTIN_LIBC_BUFFERED_PRINTF
#define BUILTIN_LIBC_BUFFERED_PRINTF 0
#endif

#ifndef BUILTIN_LIBC_BUFFERED_PRINT_SIZE
#define BUILTIN_LIBC_BUFFERED_PRINT_SIZE 128
#endif

struct str_context {
    char *str;
    uint32 max;
    uint32 count;
#if BUILTIN_LIBC_BUFFERED_PRINTF != 0
    char print_buf[BUILTIN_LIBC_BUFFERED_PRINT_SIZE];
    uint32 print_buf_size;
#endif
};

static int
sprintf_out(int c, struct str_context *ctx)
{
    if (!ctx->str || ctx->count >= ctx->max) {
        ctx->count++;
        return c;
    }

    if (ctx->count == ctx->max - 1) {
        ctx->str[ctx->count++] = '\0';
    }
    else {
        ctx->str[ctx->count++] = (char)c;
    }

    return c;
}

#if BUILTIN_LIBC_BUFFERED_PRINTF != 0
static int
printf_out(int c, struct str_context *ctx)
{
    if (c == '\n') {
        ctx->print_buf[ctx->print_buf_size] = '\0';
        os_printf("%s\n", ctx->print_buf);
        ctx->print_buf_size = 0;
    }
    else if (ctx->print_buf_size >= sizeof(ctx->print_buf) - 2) {
        ctx->print_buf[ctx->print_buf_size++] = (char)c;
        ctx->print_buf[ctx->print_buf_size] = '\0';
        os_printf("%s\n", ctx->print_buf);
        ctx->print_buf_size = 0;
    }
    else {
        ctx->print_buf[ctx->print_buf_size++] = (char)c;
    }
    ctx->count++;
    return c;
}
#else
static int
printf_out(int c, struct str_context *ctx)
{
    os_printf("%c", c);
    ctx->count++;
    return c;
}
#endif

static int
printf_wrapper(wasm_exec_env_t exec_env, const char *format, _va_list va_args)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    struct str_context ctx = { 0 };

    memset(&ctx, 0, sizeof(ctx));

    /* format has been checked by runtime */
    if (!validate_native_addr(va_args, (uint64)sizeof(int32)))
        return 0;

    if (!_vprintf_wa((out_func_t)printf_out, &ctx, format, va_args,
                     module_inst))
        return 0;

#if BUILTIN_LIBC_BUFFERED_PRINTF != 0
    if (ctx.print_buf_size > 0)
        os_printf("%s", ctx.print_buf);
#endif

    return (int)ctx.count;
}

static int
sprintf_wrapper(wasm_exec_env_t exec_env, char *str, const char *format,
                _va_list va_args)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint8 *native_end_offset;
    struct str_context ctx;

    /* str and format have been checked by runtime */
    if (!validate_native_addr(va_args, (uint64)sizeof(uint32)))
        return 0;

    if (!wasm_runtime_get_native_addr_range(module_inst, (uint8 *)str, NULL,
                                            &native_end_offset)) {
        wasm_runtime_set_exception(module_inst, "out of bounds memory access");
        return 0;
    }

    ctx.str = str;
    ctx.max = (uint32)(native_end_offset - (uint8 *)str);
    ctx.count = 0;

    if (!_vprintf_wa((out_func_t)sprintf_out, &ctx, format, va_args,
                     module_inst))
        return 0;

    if (ctx.count < ctx.max) {
        str[ctx.count] = '\0';
    }

    return (int)ctx.count;
}

static int
snprintf_wrapper(wasm_exec_env_t exec_env, char *str, uint32 size,
                 const char *format, _va_list va_args)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    struct str_context ctx;

    /* str and format have been checked by runtime */
    if (!validate_native_addr(va_args, (uint64)sizeof(uint32)))
        return 0;

    ctx.str = str;
    ctx.max = size;
    ctx.count = 0;

    if (!_vprintf_wa((out_func_t)sprintf_out, &ctx, format, va_args,
                     module_inst))
        return 0;

    if (ctx.count < ctx.max) {
        str[ctx.count] = '\0';
    }

    return (int)ctx.count;
}

static int
puts_wrapper(wasm_exec_env_t exec_env, const char *str)
{
    (void)exec_env;

    return os_printf("%s\n", str);
}

static int
putchar_wrapper(wasm_exec_env_t exec_env, int c)
{
    (void)exec_env;

    os_printf("%c", c);
    return 1;
}

static uint32
strdup_wrapper(wasm_exec_env_t exec_env, const char *str)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char *str_ret;
    uint32 len;
    uint32 str_ret_offset = 0;

    /* str has been checked by runtime */
    if (str) {
        len = (uint32)strlen(str) + 1;

        str_ret_offset = (uint32)module_malloc((uint64)len, (void **)&str_ret);
        if (str_ret_offset) {
            bh_memcpy_s(str_ret, len, str, len);
        }
    }

    return str_ret_offset;
}

static uint32
_strdup_wrapper(wasm_exec_env_t exec_env, const char *str)
{
    return strdup_wrapper(exec_env, str);
}

static int32
memcmp_wrapper(wasm_exec_env_t exec_env, const void *s1, const void *s2,
               uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    /* s2 has been checked by runtime */
    if (!validate_native_addr((void *)s1, (uint64)size))
        return 0;

    return memcmp(s1, s2, size);
}

static uint32
memcpy_wrapper(wasm_exec_env_t exec_env, void *dst, const void *src,
               uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 dst_offset = (uint32)addr_native_to_app(dst);

    if (size == 0)
        return dst_offset;

    /* src has been checked by runtime */
    if (!validate_native_addr(dst, (uint64)size))
        return dst_offset;

    bh_memcpy_s(dst, size, src, size);
    return dst_offset;
}

static uint32
memmove_wrapper(wasm_exec_env_t exec_env, void *dst, void *src, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 dst_offset = (uint32)addr_native_to_app(dst);

    if (size == 0)
        return dst_offset;

    /* src has been checked by runtime */
    if (!validate_native_addr(dst, (uint64)size))
        return dst_offset;

    memmove(dst, src, size);
    return dst_offset;
}

static uint32
memset_wrapper(wasm_exec_env_t exec_env, void *s, int32 c, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 s_offset = (uint32)addr_native_to_app(s);

    if (!validate_native_addr(s, (uint64)size))
        return s_offset;

    memset(s, c, size);
    return s_offset;
}

static uint32
strchr_wrapper(wasm_exec_env_t exec_env, const char *s, int32 c)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char *ret;

    /* s has been checked by runtime */
    ret = strchr(s, c);
    return ret ? (uint32)addr_native_to_app(ret) : 0;
}

static int32
strcmp_wrapper(wasm_exec_env_t exec_env, const char *s1, const char *s2)
{
    (void)exec_env;

    /* s1 and s2 have been checked by runtime */
    return strcmp(s1, s2);
}

static int32
strncmp_wrapper(wasm_exec_env_t exec_env, const char *s1, const char *s2,
                uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    /* s2 has been checked by runtime */
    if (!validate_native_addr((void *)s1, (uint64)size))
        return 0;

    return strncmp(s1, s2, size);
}

static uint32
strcpy_wrapper(wasm_exec_env_t exec_env, char *dst, const char *src)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 len = (uint32)strlen(src) + 1;

    /* src has been checked by runtime */
    if (!validate_native_addr(dst, (uint64)len))
        return 0;

#ifndef BH_PLATFORM_WINDOWS
    strncpy(dst, src, len);
#else
    strncpy_s(dst, len, src, len);
#endif
    return (uint32)addr_native_to_app(dst);
}

static uint32
strncpy_wrapper(wasm_exec_env_t exec_env, char *dst, const char *src,
                uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    /* src has been checked by runtime */
    if (!validate_native_addr(dst, (uint64)size))
        return 0;

#ifndef BH_PLATFORM_WINDOWS
    strncpy(dst, src, size);
#else
    strncpy_s(dst, size, src, size);
#endif
    return (uint32)addr_native_to_app(dst);
}

static uint32
strlen_wrapper(wasm_exec_env_t exec_env, const char *s)
{
    (void)exec_env;

    /* s has been checked by runtime */
    return (uint32)strlen(s);
}

static uint32
malloc_wrapper(wasm_exec_env_t exec_env, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    return (uint32)module_malloc((uint64)size, NULL);
}

static uint32
calloc_wrapper(wasm_exec_env_t exec_env, uint32 nmemb, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint64 total_size = (uint64)nmemb * (uint64)size;
    uint32 ret_offset = 0;
    uint8 *ret_ptr;

    if (total_size >= UINT32_MAX)
        return 0;

    ret_offset = (uint32)module_malloc(total_size, (void **)&ret_ptr);
    if (ret_offset) {
        memset(ret_ptr, 0, (uint32)total_size);
    }

    return ret_offset;
}

static uint32
realloc_wrapper(wasm_exec_env_t exec_env, uint32 ptr, uint32 new_size)
{
    uint64 ret_offset = 0;
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    ret_offset = wasm_runtime_module_realloc(module_inst, ptr, new_size, NULL);
    bh_assert(ret_offset < UINT32_MAX);
    return (uint32)ret_offset;
}

static void
free_wrapper(wasm_exec_env_t exec_env, void *ptr)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (!validate_native_addr(ptr, (uint64)sizeof(uint32)))
        return;

    module_free(addr_native_to_app(ptr));
}

static int32
atoi_wrapper(wasm_exec_env_t exec_env, const char *s)
{
    (void)exec_env;
    /* s has been checked by runtime */
    return atoi(s);
}

static void
exit_wrapper(wasm_exec_env_t exec_env, int32 status)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];
    snprintf(buf, sizeof(buf), "env.exit(%" PRId32 ")", status);
    wasm_runtime_set_exception(module_inst, buf);
}

static int32
strtol_wrapper(wasm_exec_env_t exec_env, const char *nptr, char **endptr,
               int32 base)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    int32 num = 0;

    /* nptr has been checked by runtime */
    if (!validate_native_addr(endptr, (uint64)sizeof(uint32)))
        return 0;

    num = (int32)strtol(nptr, endptr, base);
    *(uint32 *)endptr = (uint32)addr_native_to_app(*endptr);

    return num;
}

static uint32
strtoul_wrapper(wasm_exec_env_t exec_env, const char *nptr, char **endptr,
                int32 base)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 num = 0;

    /* nptr has been checked by runtime */
    if (!validate_native_addr(endptr, (uint64)sizeof(uint32)))
        return 0;

    num = (uint32)strtoul(nptr, endptr, base);
    *(uint32 *)endptr = (uint32)addr_native_to_app(*endptr);

    return num;
}

static uint32
memchr_wrapper(wasm_exec_env_t exec_env, const void *s, int32 c, uint32 n)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    void *res;

    if (!validate_native_addr((void *)s, (uint64)n))
        return 0;

    res = memchr(s, c, n);
    return (uint32)addr_native_to_app(res);
}

static int32
strncasecmp_wrapper(wasm_exec_env_t exec_env, const char *s1, const char *s2,
                    uint32 n)
{
    (void)exec_env;

    /* s1 and s2 have been checked by runtime */
    return strncasecmp(s1, s2, n);
}

static uint32
strspn_wrapper(wasm_exec_env_t exec_env, const char *s, const char *accept)
{
    (void)exec_env;

    /* s and accept have been checked by runtime */
    return (uint32)strspn(s, accept);
}

static uint32
strcspn_wrapper(wasm_exec_env_t exec_env, const char *s, const char *reject)
{
    (void)exec_env;

    /* s and reject have been checked by runtime */
    return (uint32)strcspn(s, reject);
}

static uint32
strstr_wrapper(wasm_exec_env_t exec_env, const char *s, const char *find)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    /* s and find have been checked by runtime */
    char *res = strstr(s, find);
    return (uint32)addr_native_to_app(res);
}

static int32
isupper_wrapper(wasm_exec_env_t exec_env, int32 c)
{
    (void)exec_env;

    return isupper(c);
}

static int32
isalpha_wrapper(wasm_exec_env_t exec_env, int32 c)
{
    (void)exec_env;

    return isalpha(c);
}

static int32
isspace_wrapper(wasm_exec_env_t exec_env, int32 c)
{
    (void)exec_env;

    return isspace(c);
}

static int32
isgraph_wrapper(wasm_exec_env_t exec_env, int32 c)
{
    (void)exec_env;

    return isgraph(c);
}

static int32
isprint_wrapper(wasm_exec_env_t exec_env, int32 c)
{
    (void)exec_env;

    return isprint(c);
}

static int32
isdigit_wrapper(wasm_exec_env_t exec_env, int32 c)
{
    (void)exec_env;

    return isdigit(c);
}

static int32
isxdigit_wrapper(wasm_exec_env_t exec_env, int32 c)
{
    (void)exec_env;

    return isxdigit(c);
}

static int32
tolower_wrapper(wasm_exec_env_t exec_env, int32 c)
{
    (void)exec_env;

    return tolower(c);
}

static int32
toupper_wrapper(wasm_exec_env_t exec_env, int32 c)
{
    (void)exec_env;

    return toupper(c);
}

static int32
isalnum_wrapper(wasm_exec_env_t exec_env, int32 c)
{
    (void)exec_env;

    return isalnum(c);
}

static uint32
emscripten_memcpy_big_wrapper(wasm_exec_env_t exec_env, void *dst,
                              const void *src, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 dst_offset = (uint32)addr_native_to_app(dst);

    /* src has been checked by runtime */
    if (!validate_native_addr(dst, (uint64)size))
        return dst_offset;

    bh_memcpy_s(dst, size, src, size);
    return dst_offset;
}

static void
abort_wrapper(wasm_exec_env_t exec_env, int32 code)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];
    snprintf(buf, sizeof(buf), "env.abort(%" PRId32 ")", code);
    wasm_runtime_set_exception(module_inst, buf);
}

static void
abortStackOverflow_wrapper(wasm_exec_env_t exec_env, int32 code)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];
    snprintf(buf, sizeof(buf), "env.abortStackOverflow(%" PRId32 ")", code);
    wasm_runtime_set_exception(module_inst, buf);
}

static void
nullFunc_X_wrapper(wasm_exec_env_t exec_env, int32 code)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];
    snprintf(buf, sizeof(buf), "env.nullFunc_X(%" PRId32 ")", code);
    wasm_runtime_set_exception(module_inst, buf);
}

static uint32
__cxa_allocate_exception_wrapper(wasm_exec_env_t exec_env, uint32 thrown_size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 exception = (uint32)module_malloc((uint64)thrown_size, NULL);
    if (!exception)
        return 0;

    return exception;
}

static void
__cxa_begin_catch_wrapper(wasm_exec_env_t exec_env, void *exception_object)
{
    (void)exec_env;
    (void)exception_object;
}

static void
__cxa_throw_wrapper(wasm_exec_env_t exec_env, void *thrown_exception,
                    void *tinfo, uint32 table_elem_idx)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];

    (void)thrown_exception;
    (void)tinfo;
    (void)table_elem_idx;

    snprintf(buf, sizeof(buf), "%s", "exception thrown by stdc++");
    wasm_runtime_set_exception(module_inst, buf);
}

struct timespec_app {
    int64 tv_sec;
    int32 tv_nsec;
};

static uint32
clock_gettime_wrapper(wasm_exec_env_t exec_env, uint32 clk_id,
                      struct timespec_app *ts_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint64 time;

    (void)clk_id;

    if (!validate_native_addr(ts_app, (uint64)sizeof(struct timespec_app)))
        return (uint32)-1;

    time = os_time_get_boot_us();
    ts_app->tv_sec = time / 1000000;
    ts_app->tv_nsec = (time % 1000000) * 1000;

    return (uint32)0;
}

static uint64
clock_wrapper(wasm_exec_env_t exec_env)
{
    (void)exec_env;

    /* Convert to nano seconds as CLOCKS_PER_SEC in wasi-sdk */

    return os_time_get_boot_us() * 1000;
}

#if WASM_ENABLE_SPEC_TEST != 0
static void
print_wrapper(wasm_exec_env_t exec_env)
{
    os_printf("in specttest.print()\n");
}

static void
print_i32_wrapper(wasm_exec_env_t exec_env, int32 i32)
{
    os_printf("in specttest.print_i32(%" PRId32 ")\n", i32);
}

static void
print_i64_wrapper(wasm_exec_env_t exec_env, int64 i64)
{
    os_printf("in specttest.print_i64(%" PRId64 ")\n", i64);
}

static void
print_i32_f32_wrapper(wasm_exec_env_t exec_env, int32 i32, float f32)
{
    os_printf("in specttest.print_i32_f32(%" PRId32 ", %f)\n", i32, f32);
}

static void
print_f64_f64_wrapper(wasm_exec_env_t exec_env, double f64_1, double f64_2)
{
    os_printf("in specttest.print_f64_f64(%f, %f)\n", f64_1, f64_2);
}

static void
print_f32_wrapper(wasm_exec_env_t exec_env, float f32)
{
    os_printf("in specttest.print_f32(%f)\n", f32);
}

static void
print_f64_wrapper(wasm_exec_env_t exec_env, double f64)
{
    os_printf("in specttest.print_f64(%f)\n", f64);
}
#endif /* WASM_ENABLE_SPEC_TEST */

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_libc_builtin[] = {
    REG_NATIVE_FUNC(printf, "($*)i"),
    REG_NATIVE_FUNC(sprintf, "($$*)i"),
    REG_NATIVE_FUNC(snprintf, "(*~$*)i"),
    { "vprintf", printf_wrapper, "($*)i", NULL },
    { "vsprintf", sprintf_wrapper, "($$*)i", NULL },
    { "vsnprintf", snprintf_wrapper, "(*~$*)i", NULL },
    REG_NATIVE_FUNC(puts, "($)i"),
    REG_NATIVE_FUNC(putchar, "(i)i"),
    REG_NATIVE_FUNC(memcmp, "(**~)i"),
    REG_NATIVE_FUNC(memcpy, "(**~)i"),
    REG_NATIVE_FUNC(memmove, "(**~)i"),
    REG_NATIVE_FUNC(memset, "(*ii)i"),
    REG_NATIVE_FUNC(strchr, "($i)i"),
    REG_NATIVE_FUNC(strcmp, "($$)i"),
    REG_NATIVE_FUNC(strcpy, "(*$)i"),
    REG_NATIVE_FUNC(strlen, "($)i"),
    REG_NATIVE_FUNC(strncmp, "(**~)i"),
    REG_NATIVE_FUNC(strncpy, "(**~)i"),
    REG_NATIVE_FUNC(malloc, "(i)i"),
    REG_NATIVE_FUNC(realloc, "(ii)i"),
    REG_NATIVE_FUNC(calloc, "(ii)i"),
    REG_NATIVE_FUNC(strdup, "($)i"),
    /* clang may introduce __strdup */
    REG_NATIVE_FUNC(_strdup, "($)i"),
    REG_NATIVE_FUNC(free, "(*)"),
    REG_NATIVE_FUNC(atoi, "($)i"),
    REG_NATIVE_FUNC(exit, "(i)"),
    REG_NATIVE_FUNC(strtol, "($*i)i"),
    REG_NATIVE_FUNC(strtoul, "($*i)i"),
    REG_NATIVE_FUNC(memchr, "(*ii)i"),
    REG_NATIVE_FUNC(strncasecmp, "($$i)i"),
    REG_NATIVE_FUNC(strspn, "($$)i"),
    REG_NATIVE_FUNC(strcspn, "($$)i"),
    REG_NATIVE_FUNC(strstr, "($$)i"),
    REG_NATIVE_FUNC(isupper, "(i)i"),
    REG_NATIVE_FUNC(isalpha, "(i)i"),
    REG_NATIVE_FUNC(isspace, "(i)i"),
    REG_NATIVE_FUNC(isgraph, "(i)i"),
    REG_NATIVE_FUNC(isprint, "(i)i"),
    REG_NATIVE_FUNC(isdigit, "(i)i"),
    REG_NATIVE_FUNC(isxdigit, "(i)i"),
    REG_NATIVE_FUNC(tolower, "(i)i"),
    REG_NATIVE_FUNC(toupper, "(i)i"),
    REG_NATIVE_FUNC(isalnum, "(i)i"),
    REG_NATIVE_FUNC(emscripten_memcpy_big, "(**~)i"),
    REG_NATIVE_FUNC(abort, "(i)"),
    REG_NATIVE_FUNC(abortStackOverflow, "(i)"),
    REG_NATIVE_FUNC(nullFunc_X, "(i)"),
    REG_NATIVE_FUNC(__cxa_allocate_exception, "(i)i"),
    REG_NATIVE_FUNC(__cxa_begin_catch, "(*)"),
    REG_NATIVE_FUNC(__cxa_throw, "(**i)"),
    REG_NATIVE_FUNC(clock_gettime, "(i*)i"),
    REG_NATIVE_FUNC(clock, "()I"),
};

#if WASM_ENABLE_SPEC_TEST != 0
static NativeSymbol native_symbols_spectest[] = {
    REG_NATIVE_FUNC(print, "()"),
    REG_NATIVE_FUNC(print_i32, "(i)"),
    REG_NATIVE_FUNC(print_i64, "(I)"),
    REG_NATIVE_FUNC(print_i32_f32, "(if)"),
    REG_NATIVE_FUNC(print_f64_f64, "(FF)"),
    REG_NATIVE_FUNC(print_f32, "(f)"),
    REG_NATIVE_FUNC(print_f64, "(F)")
};
#endif

uint32
get_libc_builtin_export_apis(NativeSymbol **p_libc_builtin_apis)
{
    *p_libc_builtin_apis = native_symbols_libc_builtin;
    return sizeof(native_symbols_libc_builtin) / sizeof(NativeSymbol);
}

#if WASM_ENABLE_SPEC_TEST != 0
uint32
get_spectest_export_apis(NativeSymbol **p_libc_builtin_apis)
{
    *p_libc_builtin_apis = native_symbols_spectest;
    return sizeof(native_symbols_spectest) / sizeof(NativeSymbol);
}
#endif

/*************************************
 * Global Variables                  *
 *************************************/

typedef struct WASMNativeGlobalDef {
    const char *module_name;
    const char *global_name;
    uint8 type;
    bool is_mutable;
    WASMValue value;
} WASMNativeGlobalDef;

static WASMNativeGlobalDef native_global_defs[] = {
#if WASM_ENABLE_SPEC_TEST != 0
    { "spectest", "global_i32", VALUE_TYPE_I32, false, .value.i32 = 666 },
    { "spectest", "global_i64", VALUE_TYPE_I64, false, .value.i64 = 666 },
    { "spectest", "global_f32", VALUE_TYPE_F32, false, .value.f32 = 666.6 },
    { "spectest", "global_f64", VALUE_TYPE_F64, false, .value.f64 = 666.6 },
    { "test", "global-i32", VALUE_TYPE_I32, false, .value.i32 = 0 },
    { "test", "global-f32", VALUE_TYPE_F32, false, .value.f32 = 0 },
    { "test", "global-mut-i32", VALUE_TYPE_I32, true, .value.i32 = 0 },
    { "test", "global-mut-i64", VALUE_TYPE_I64, true, .value.i64 = 0 },
    { "test", "g", VALUE_TYPE_I32, true, .value.i32 = 0 },
#if WASM_ENABLE_GC != 0
    { "G", "g", VALUE_TYPE_I32, false, .value.i32 = 4 },
    { "M", "g", REF_TYPE_HT_NON_NULLABLE, false, .value.gc_obj = 0 },
#endif
#endif
    { "global", "NaN", VALUE_TYPE_F64, .value.u64 = 0x7FF8000000000000LL },
    { "global", "Infinity", VALUE_TYPE_F64, .value.u64 = 0x7FF0000000000000LL }
};

bool
wasm_native_lookup_libc_builtin_global(const char *module_name,
                                       const char *global_name,
                                       WASMGlobalImport *global)
{
    uint32 size = sizeof(native_global_defs) / sizeof(WASMNativeGlobalDef);
    WASMNativeGlobalDef *global_def = native_global_defs;
    WASMNativeGlobalDef *global_def_end = global_def + size;

    if (!module_name || !global_name || !global)
        return false;

    /* Lookup constant globals which can be defined by table */
    while (global_def < global_def_end) {
        if (!strcmp(global_def->module_name, module_name)
            && !strcmp(global_def->global_name, global_name)) {
            global->type.val_type = global_def->type;
            global->type.is_mutable = global_def->is_mutable;
            global->global_data_linked = global_def->value;
            return true;
        }
        global_def++;
    }

    return false;
}
