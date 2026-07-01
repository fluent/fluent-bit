/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "uvwasi.h"
#include "bh_platform.h"
#include "wasm_export.h"

/* clang-format off */
#define get_module_inst(exec_env) \
    wasm_runtime_get_module_inst(exec_env)

#define validate_app_addr(offset, size) \
    wasm_runtime_validate_app_addr(module_inst, offset, size)

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

// uvwasi_errno_t is typedef'd to uint16 which is correct according to the ABI
// specification. However, in WASM, the smallest integer type is int32. If we
// return uint16, we would rely on language SDKs to implement the correct
// behaviour of casting to uint16 before checking the value or using it any way.
// Failure to do so can cause tricky bugs as the upper 16 bits of the error
// result are not guaranteed to be zero'ed by us so the result essentially
// contains garbage from the WASM app perspective. To prevent this, we return
// uint32 directly instead so as not to be reliant on the correct behaviour of
// any current/future SDK implementations.
#define wasi_errno_t uint32_t
#define wasi_fd_t uvwasi_fd_t
#define wasi_clockid_t uvwasi_clockid_t
#define wasi_timestamp_t uvwasi_timestamp_t
#define wasi_filesize_t uvwasi_filesize_t
#define wasi_prestat_app_t uvwasi_prestat_app_t
#define wasi_filedelta_t uvwasi_filedelta_t
#define wasi_whence_t uvwasi_whence_t
#define wasi_fdflags_t uvwasi_fdflags_t
#define wasi_rights_t uvwasi_rights_t
#define wasi_advice_t uvwasi_advice_t
#define wasi_lookupflags_t uvwasi_lookupflags_t
#define wasi_preopentype_t uvwasi_preopentype_t
#define wasi_fdstat_t uvwasi_fdstat_t
#define wasi_oflags_t uvwasi_oflags_t
#define wasi_dircookie_t uvwasi_dircookie_t
#define wasi_filestat_t uvwasi_filestat_t
#define wasi_fstflags_t uvwasi_fstflags_t
#define wasi_subscription_t uvwasi_subscription_t
#define wasi_event_t uvwasi_event_t
#define wasi_exitcode_t uvwasi_exitcode_t
#define wasi_signal_t uvwasi_signal_t
#define wasi_riflags_t uvwasi_riflags_t
#define wasi_roflags_t uvwasi_roflags_t
#define wasi_siflags_t uvwasi_siflags_t
#define wasi_sdflags_t uvwasi_sdflags_t
#define wasi_iovec_t uvwasi_iovec_t
#define wasi_ciovec_t uvwasi_ciovec_t

typedef struct wasi_prestat_app {
    wasi_preopentype_t pr_type;
    uint32 pr_name_len;
} wasi_prestat_app_t;

typedef struct iovec_app {
    uint32 buf_offset;
    uint32 buf_len;
} iovec_app_t;

typedef struct WASIContext {
    uvwasi_t uvwasi;
    uint32_t exit_code;
} WASIContext;

void *
wasm_runtime_get_wasi_ctx(wasm_module_inst_t module_inst);

static uvwasi_t *
get_wasi_ctx(wasm_module_inst_t module_inst)
{
    WASIContext *ctx = wasm_runtime_get_wasi_ctx(module_inst);
    if (ctx == NULL) {
        return NULL;
    }
    return &ctx->uvwasi;
}

static wasi_errno_t
wasi_args_get(wasm_exec_env_t exec_env, uint32 *argv_offsets, char *argv_buf)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    uvwasi_size_t argc, argv_buf_size, i;
    char **argv;
    uint64 total_size;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    err = uvwasi_args_sizes_get(uvwasi, &argc, &argv_buf_size);
    if (err)
        return err;

    total_size = sizeof(int32) * ((uint64)argc + 1);
    if (total_size >= UINT32_MAX
        || !validate_native_addr(argv_offsets, total_size)
        || argv_buf_size >= UINT32_MAX
        || !validate_native_addr(argv_buf, (uint64)argv_buf_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(char *) * ((uint64)argc + 1);
    if (total_size >= UINT32_MAX
        || !(argv = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    err = uvwasi_args_get(uvwasi, argv, argv_buf);
    if (err) {
        wasm_runtime_free(argv);
        return err;
    }

    for (i = 0; i < argc; i++)
        argv_offsets[i] = (uint32)addr_native_to_app(argv[i]);

    wasm_runtime_free(argv);
    return 0;
}

static wasi_errno_t
wasi_args_sizes_get(wasm_exec_env_t exec_env, uint32 *argc_app,
                    uint32 *argv_buf_size_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    uvwasi_size_t argc, argv_buf_size;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(argc_app, (uint64)sizeof(uint32))
        || !validate_native_addr(argv_buf_size_app, (uint64)sizeof(uint32)))
        return (wasi_errno_t)-1;

    err = uvwasi_args_sizes_get(uvwasi, &argc, &argv_buf_size);
    if (err)
        return err;

    *argc_app = (uint32)argc;
    *argv_buf_size_app = (uint32)argv_buf_size;
    return 0;
}

static wasi_errno_t
wasi_clock_res_get(wasm_exec_env_t exec_env, wasi_clockid_t clock_id,
                   wasi_timestamp_t *resolution)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!validate_native_addr(resolution, (uint64)sizeof(wasi_timestamp_t)))
        return (wasi_errno_t)-1;

    return uvwasi_clock_res_get(uvwasi, clock_id, resolution);
}

static wasi_errno_t
wasi_clock_time_get(wasm_exec_env_t exec_env, wasi_clockid_t clock_id,
                    wasi_timestamp_t precision, wasi_timestamp_t *time)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!validate_native_addr(time, (uint64)sizeof(wasi_timestamp_t)))
        return (wasi_errno_t)-1;

    return uvwasi_clock_time_get(uvwasi, clock_id, precision, time);
}

static wasi_errno_t
wasi_environ_get(wasm_exec_env_t exec_env, uint32 *environ_offsets,
                 char *environ_buf)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    uvwasi_size_t environ_count, environ_buf_size, i;
    uint64 total_size;
    char **environs;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    err = uvwasi_environ_sizes_get(uvwasi, &environ_count, &environ_buf_size);
    if (err)
        return err;

    if (environ_count == 0)
        return 0;

    total_size = sizeof(int32) * ((uint64)environ_count + 1);
    if (total_size >= UINT32_MAX
        || !validate_native_addr(environ_offsets, total_size)
        || environ_buf_size >= UINT32_MAX
        || !validate_native_addr(environ_buf, (uint64)environ_buf_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(char *) * (((uint64)environ_count + 1));

    if (total_size >= UINT32_MAX
        || !(environs = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    err = uvwasi_environ_get(uvwasi, environs, environ_buf);
    if (err) {
        wasm_runtime_free(environs);
        return err;
    }

    for (i = 0; i < environ_count; i++)
        environ_offsets[i] = (uint32)addr_native_to_app(environs[i]);

    wasm_runtime_free(environs);
    return 0;
}

static wasi_errno_t
wasi_environ_sizes_get(wasm_exec_env_t exec_env, uint32 *environ_count_app,
                       uint32 *environ_buf_size_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    uvwasi_size_t environ_count, environ_buf_size;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(environ_count_app, (uint64)sizeof(uint32))
        || !validate_native_addr(environ_buf_size_app, (uint64)sizeof(uint32)))
        return (wasi_errno_t)-1;

    err = uvwasi_environ_sizes_get(uvwasi, &environ_count, &environ_buf_size);
    if (err)
        return err;

    *environ_count_app = (uint32)environ_count;
    *environ_buf_size_app = (uint32)environ_buf_size;
    return 0;
}

static wasi_errno_t
wasi_fd_prestat_get(wasm_exec_env_t exec_env, wasi_fd_t fd,
                    wasi_prestat_app_t *prestat_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    uvwasi_prestat_t prestat;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(prestat_app, (uint64)sizeof(wasi_prestat_app_t)))
        return (wasi_errno_t)-1;

    err = uvwasi_fd_prestat_get(uvwasi, fd, &prestat);
    if (err)
        return err;

    prestat_app->pr_type = prestat.pr_type;
    prestat_app->pr_name_len = (uint32)prestat.u.dir.pr_name_len;
    return 0;
}

static wasi_errno_t
wasi_fd_prestat_dir_name(wasm_exec_env_t exec_env, wasi_fd_t fd, char *path,
                         uint32 path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_prestat_dir_name(uvwasi, fd, path, path_len);
}

static wasi_errno_t
wasi_fd_close(wasm_exec_env_t exec_env, wasi_fd_t fd)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_close(uvwasi, fd);
}

static wasi_errno_t
wasi_fd_datasync(wasm_exec_env_t exec_env, wasi_fd_t fd)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_datasync(uvwasi, fd);
}

static wasi_errno_t
wasi_fd_pread(wasm_exec_env_t exec_env, wasi_fd_t fd, iovec_app_t *iovec_app,
              uint32 iovs_len, wasi_filesize_t offset, uint32 *nread_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    wasi_iovec_t *iovec, *iovec_begin;
    uint64 total_size;
    uvwasi_size_t nread;
    uint32 i;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)iovs_len;
    if (!validate_native_addr(nread_app, (uint64)sizeof(uint32))
        || total_size >= UINT32_MAX
        || !validate_native_addr(iovec_app, total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_iovec_t) * (uint64)iovs_len;
    if (total_size >= UINT32_MAX
        || !(iovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    iovec = iovec_begin;
    for (i = 0; i < iovs_len; i++, iovec_app++, iovec++) {
        if (!validate_app_addr((uint64)iovec_app->buf_offset,
                               (uint64)iovec_app->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        iovec->buf = (void *)addr_app_to_native((uint64)iovec_app->buf_offset);
        iovec->buf_len = iovec_app->buf_len;
    }

    err = uvwasi_fd_pread(uvwasi, fd, iovec_begin, iovs_len, offset, &nread);
    if (err)
        goto fail;

    *nread_app = (uint32)nread;

    /* success */
    err = 0;

fail:
    wasm_runtime_free(iovec_begin);
    return err;
}

static wasi_errno_t
wasi_fd_pwrite(wasm_exec_env_t exec_env, wasi_fd_t fd,
               const iovec_app_t *iovec_app, uint32 iovs_len,
               wasi_filesize_t offset, uint32 *nwritten_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    wasi_ciovec_t *ciovec, *ciovec_begin;
    uint64 total_size;
    uvwasi_size_t nwritten;
    uint32 i;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)iovs_len;
    if (!validate_native_addr(nwritten_app, (uint64)sizeof(uint32))
        || total_size >= UINT32_MAX
        || !validate_native_addr((void *)iovec_app, total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_ciovec_t) * (uint64)iovs_len;
    if (total_size >= UINT32_MAX
        || !(ciovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    ciovec = ciovec_begin;
    for (i = 0; i < iovs_len; i++, iovec_app++, ciovec++) {
        if (!validate_app_addr((uint64)iovec_app->buf_offset,
                               (uint64)iovec_app->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        ciovec->buf = (char *)addr_app_to_native((uint64)iovec_app->buf_offset);
        ciovec->buf_len = iovec_app->buf_len;
    }

    err =
        uvwasi_fd_pwrite(uvwasi, fd, ciovec_begin, iovs_len, offset, &nwritten);
    if (err)
        goto fail;

    *nwritten_app = (uint32)nwritten;

    /* success */
    err = 0;

fail:
    wasm_runtime_free(ciovec_begin);
    return err;
}

static wasi_errno_t
wasi_fd_read(wasm_exec_env_t exec_env, wasi_fd_t fd,
             const iovec_app_t *iovec_app, uint32 iovs_len, uint32 *nread_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    wasi_iovec_t *iovec, *iovec_begin;
    uint64 total_size;
    uvwasi_size_t nread;
    uint32 i;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)iovs_len;
    if (!validate_native_addr(nread_app, (uint64)sizeof(uint32))
        || total_size >= UINT32_MAX
        || !validate_native_addr((void *)iovec_app, total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_iovec_t) * (uint64)iovs_len;
    if (total_size >= UINT32_MAX
        || !(iovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    iovec = iovec_begin;
    for (i = 0; i < iovs_len; i++, iovec_app++, iovec++) {
        if (!validate_app_addr((uint64)iovec_app->buf_offset,
                               (uint64)iovec_app->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        iovec->buf = (void *)addr_app_to_native((uint64)iovec_app->buf_offset);
        iovec->buf_len = iovec_app->buf_len;
    }

    err = uvwasi_fd_read(uvwasi, fd, iovec_begin, iovs_len, &nread);
    if (err)
        goto fail;

    *nread_app = (uint32)nread;

    /* success */
    err = 0;

fail:
    wasm_runtime_free(iovec_begin);
    return err;
}

static wasi_errno_t
wasi_fd_renumber(wasm_exec_env_t exec_env, wasi_fd_t from, wasi_fd_t to)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_renumber(uvwasi, from, to);
}

static wasi_errno_t
wasi_fd_seek(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_filedelta_t offset,
             wasi_whence_t whence, wasi_filesize_t *newoffset)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(newoffset, (uint64)sizeof(wasi_filesize_t)))
        return (wasi_errno_t)-1;

    return uvwasi_fd_seek(uvwasi, fd, offset, whence, newoffset);
}

static wasi_errno_t
wasi_fd_tell(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_filesize_t *newoffset)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(newoffset, (uint64)sizeof(wasi_filesize_t)))
        return (wasi_errno_t)-1;

    return uvwasi_fd_tell(uvwasi, fd, newoffset);
}

static wasi_errno_t
wasi_fd_fdstat_get(wasm_exec_env_t exec_env, wasi_fd_t fd,
                   wasi_fdstat_t *fdstat_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    wasi_fdstat_t fdstat;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(fdstat_app, (uint64)sizeof(wasi_fdstat_t)))
        return (wasi_errno_t)-1;

    err = uvwasi_fd_fdstat_get(uvwasi, fd, &fdstat);
    if (err)
        return err;

    memcpy(fdstat_app, &fdstat, sizeof(wasi_fdstat_t));
    return 0;
}

static wasi_errno_t
wasi_fd_fdstat_set_flags(wasm_exec_env_t exec_env, wasi_fd_t fd,
                         wasi_fdflags_t flags)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_fdstat_set_flags(uvwasi, fd, flags);
}

static wasi_errno_t
wasi_fd_fdstat_set_rights(wasm_exec_env_t exec_env, wasi_fd_t fd,
                          wasi_rights_t fs_rights_base,
                          wasi_rights_t fs_rights_inheriting)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_fdstat_set_rights(uvwasi, fd, fs_rights_base,
                                       fs_rights_inheriting);
}

static wasi_errno_t
wasi_fd_sync(wasm_exec_env_t exec_env, wasi_fd_t fd)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_sync(uvwasi, fd);
}

static wasi_errno_t
wasi_fd_write(wasm_exec_env_t exec_env, wasi_fd_t fd,
              const iovec_app_t *iovec_app, uint32 iovs_len,
              uint32 *nwritten_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    wasi_ciovec_t *ciovec, *ciovec_begin;
    uint64 total_size;
    uvwasi_size_t nwritten;
    uint32 i;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)iovs_len;
    if (!validate_native_addr(nwritten_app, (uint64)sizeof(uint32))
        || total_size >= UINT32_MAX
        || !validate_native_addr((void *)iovec_app, total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_ciovec_t) * (uint64)iovs_len;
    if (total_size >= UINT32_MAX
        || !(ciovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    ciovec = ciovec_begin;
    for (i = 0; i < iovs_len; i++, iovec_app++, ciovec++) {
        if (!validate_app_addr((uint64)iovec_app->buf_offset,
                               (uint64)iovec_app->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        ciovec->buf = (char *)addr_app_to_native((uint64)iovec_app->buf_offset);
        ciovec->buf_len = iovec_app->buf_len;
    }

#ifndef BH_VPRINTF
    err = uvwasi_fd_write(uvwasi, fd, ciovec_begin, iovs_len, &nwritten);
#else
    /* redirect stdout/stderr output to BH_VPRINTF function */
    if (fd == 1 || fd == 2) {
        int i;
        const struct iovec *iov1 = (const struct iovec *)ciovec_begin;

        nwritten = 0;
        for (i = 0; i < (int)iovs_len; i++, iov1++) {
            if (iov1->iov_len > 0 && iov1->iov_base) {
                char format[16];

                /* make up format string "%.ns" */
                snprintf(format, sizeof(format), "%%.%ds", (int)iov1->iov_len);
                nwritten += (uvwasi_size_t)os_printf(format, iov1->iov_base);
            }
        }
        err = 0;
    }
    else {
        err = uvwasi_fd_write(uvwasi, fd, ciovec_begin, iovs_len, &nwritten);
    }
#endif /* end of BH_VPRINTF */

    if (err)
        goto fail;

    *nwritten_app = (uint32)nwritten;

    /* success */
    err = 0;

fail:
    wasm_runtime_free(ciovec_begin);
    return err;
}

static wasi_errno_t
wasi_fd_advise(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_filesize_t offset,
               wasi_filesize_t len, wasi_advice_t advice)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_advise(uvwasi, fd, offset, len, advice);
}

static wasi_errno_t
wasi_fd_allocate(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_filesize_t offset,
                 wasi_filesize_t len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_allocate(uvwasi, fd, offset, len);
}

static wasi_errno_t
wasi_path_create_directory(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           const char *path, uint32 path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_path_create_directory(uvwasi, fd, path, path_len);
}

static wasi_errno_t
wasi_path_link(wasm_exec_env_t exec_env, wasi_fd_t old_fd,
               wasi_lookupflags_t old_flags, const char *old_path,
               uint32 old_path_len, wasi_fd_t new_fd, const char *new_path,
               uint32 new_path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_path_link(uvwasi, old_fd, old_flags, old_path, old_path_len,
                            new_fd, new_path, new_path_len);
}

static wasi_errno_t
wasi_path_open(wasm_exec_env_t exec_env, wasi_fd_t dirfd,
               wasi_lookupflags_t dirflags, const char *path, uint32 path_len,
               wasi_oflags_t oflags, wasi_rights_t fs_rights_base,
               wasi_rights_t fs_rights_inheriting, wasi_fdflags_t fs_flags,
               wasi_fd_t *fd_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    wasi_fd_t fd = (wasi_fd_t)-1; /* set fd_app -1 if path open failed */
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(fd_app, (uint64)sizeof(wasi_fd_t)))
        return (wasi_errno_t)-1;

    err = uvwasi_path_open(uvwasi, dirfd, dirflags, path, path_len, oflags,
                           fs_rights_base, fs_rights_inheriting, fs_flags, &fd);

    *fd_app = fd;
    return err;
}

static wasi_errno_t
wasi_fd_readdir(wasm_exec_env_t exec_env, wasi_fd_t fd, void *buf,
                uint32 buf_len, wasi_dircookie_t cookie, uint32 *bufused_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    uvwasi_size_t bufused;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(bufused_app, (uint64)sizeof(uint32)))
        return (wasi_errno_t)-1;

    err = uvwasi_fd_readdir(uvwasi, fd, buf, buf_len, cookie, &bufused);
    if (err)
        return err;

    *bufused_app = (uint32)bufused;
    return 0;
}

static wasi_errno_t
wasi_path_readlink(wasm_exec_env_t exec_env, wasi_fd_t fd, const char *path,
                   uint32 path_len, char *buf, uint32 buf_len,
                   uint32 *bufused_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    uvwasi_size_t bufused;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(bufused_app, (uint64)sizeof(uint32)))
        return (wasi_errno_t)-1;

    err = uvwasi_path_readlink(uvwasi, fd, path, path_len, buf, buf_len,
                               &bufused);
    if (err)
        return err;

    *bufused_app = (uint32)bufused;
    return 0;
}

static wasi_errno_t
wasi_path_rename(wasm_exec_env_t exec_env, wasi_fd_t old_fd,
                 const char *old_path, uint32 old_path_len, wasi_fd_t new_fd,
                 const char *new_path, uint32 new_path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_path_rename(uvwasi, old_fd, old_path, old_path_len, new_fd,
                              new_path, new_path_len);
}

static wasi_errno_t
wasi_fd_filestat_get(wasm_exec_env_t exec_env, wasi_fd_t fd,
                     wasi_filestat_t *filestat)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(filestat, (uint64)sizeof(wasi_filestat_t)))
        return (wasi_errno_t)-1;

    return uvwasi_fd_filestat_get(uvwasi, fd, filestat);
}

static wasi_errno_t
wasi_fd_filestat_set_times(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           wasi_timestamp_t st_atim, wasi_timestamp_t st_mtim,
                           wasi_fstflags_t fstflags)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_filestat_set_times(uvwasi, fd, st_atim, st_mtim, fstflags);
}

static wasi_errno_t
wasi_fd_filestat_set_size(wasm_exec_env_t exec_env, wasi_fd_t fd,
                          wasi_filesize_t st_size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_fd_filestat_set_size(uvwasi, fd, st_size);
}

static wasi_errno_t
wasi_path_filestat_get(wasm_exec_env_t exec_env, wasi_fd_t fd,
                       wasi_lookupflags_t flags, const char *path,
                       uint32 path_len, wasi_filestat_t *filestat)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(filestat, (uint64)sizeof(wasi_filestat_t)))
        return (wasi_errno_t)-1;

    return uvwasi_path_filestat_get(uvwasi, fd, flags, path, path_len,
                                    filestat);
}

static wasi_errno_t
wasi_path_filestat_set_times(wasm_exec_env_t exec_env, wasi_fd_t fd,
                             wasi_lookupflags_t flags, const char *path,
                             uint32 path_len, wasi_timestamp_t st_atim,
                             wasi_timestamp_t st_mtim, wasi_fstflags_t fstflags)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_path_filestat_set_times(uvwasi, fd, flags, path, path_len,
                                          st_atim, st_mtim, fstflags);
}

static wasi_errno_t
wasi_path_symlink(wasm_exec_env_t exec_env, const char *old_path,
                  uint32 old_path_len, wasi_fd_t fd, const char *new_path,
                  uint32 new_path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_path_symlink(uvwasi, old_path, old_path_len, fd, new_path,
                               new_path_len);
}

static wasi_errno_t
wasi_path_unlink_file(wasm_exec_env_t exec_env, wasi_fd_t fd, const char *path,
                      uint32 path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_path_unlink_file(uvwasi, fd, path, path_len);
}

static wasi_errno_t
wasi_path_remove_directory(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           const char *path, uint32 path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_path_remove_directory(uvwasi, fd, path, path_len);
}

static wasi_errno_t
wasi_poll_oneoff(wasm_exec_env_t exec_env, const wasi_subscription_t *in,
                 wasi_event_t *out, uint32 nsubscriptions, uint32 *nevents_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    uvwasi_size_t nevents;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    if (!validate_native_addr((void *)in, (uint64)sizeof(wasi_subscription_t))
        || !validate_native_addr(out, (uint64)sizeof(wasi_event_t))
        || !validate_native_addr(nevents_app, (uint64)sizeof(uint32)))
        return (wasi_errno_t)-1;

    err = uvwasi_poll_oneoff(uvwasi, in, out, nsubscriptions, &nevents);
    if (err)
        return err;

    *nevents_app = (uint32)nevents;
    return 0;
}

static void
wasi_proc_exit(wasm_exec_env_t exec_env, wasi_exitcode_t rval)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    WASIContext *wasi_ctx = wasm_runtime_get_wasi_ctx(module_inst);
    /* Here throwing exception is just to let wasm app exit,
       the upper layer should clear the exception and return
       as normal */
    wasm_runtime_set_exception(module_inst, "wasi proc exit");
    wasi_ctx->exit_code = rval;
}

static wasi_errno_t
wasi_proc_raise(wasm_exec_env_t exec_env, wasi_signal_t sig)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char buf[32];

    snprintf(buf, sizeof(buf), "%s%d", "wasi proc raise ", sig);
    wasm_runtime_set_exception(module_inst, buf);
    return 0;
}

static wasi_errno_t
wasi_random_get(wasm_exec_env_t exec_env, void *buf, uint32 buf_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    return uvwasi_random_get(uvwasi, buf, buf_len);
}

static wasi_errno_t
wasi_sock_recv(wasm_exec_env_t exec_env, wasi_fd_t sock, iovec_app_t *ri_data,
               uint32 ri_data_len, wasi_riflags_t ri_flags,
               uint32 *ro_datalen_app, wasi_roflags_t *ro_flags)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    wasi_iovec_t *iovec, *iovec_begin;
    uint64 total_size;
    uvwasi_size_t ro_datalen;
    uint32 i;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)ri_data_len;
    if (!validate_native_addr(ro_datalen_app, (uint32)sizeof(uint32))
        || !validate_native_addr(ro_flags, (uint32)sizeof(wasi_roflags_t))
        || total_size >= UINT32_MAX
        || !validate_native_addr(ri_data, (uint32)total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_iovec_t) * (uint64)ri_data_len;
    if (total_size >= UINT32_MAX
        || !(iovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    iovec = iovec_begin;
    for (i = 0; i < ri_data_len; i++, ri_data++, iovec++) {
        if (!validate_app_addr((uint64)ri_data->buf_offset,
                               (uint64)ri_data->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        iovec->buf = (void *)addr_app_to_native((uint64)ri_data->buf_offset);
        iovec->buf_len = ri_data->buf_len;
    }

    err = uvwasi_sock_recv(uvwasi, sock, iovec_begin, ri_data_len, ri_flags,
                           &ro_datalen, ro_flags);
    if (err)
        goto fail;

    *(uint32 *)ro_datalen_app = (uint32)ro_datalen;

    /* success */
    err = 0;

fail:
    wasm_runtime_free(iovec_begin);
    return err;
}

static wasi_errno_t
wasi_sock_send(wasm_exec_env_t exec_env, wasi_fd_t sock,
               const iovec_app_t *si_data, uint32 si_data_len,
               wasi_siflags_t si_flags, uint32 *so_datalen_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);
    wasi_ciovec_t *ciovec, *ciovec_begin;
    uint64 total_size;
    uvwasi_size_t so_datalen;
    uint32 i;
    wasi_errno_t err;

    if (!uvwasi)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)si_data_len;
    if (!validate_native_addr(so_datalen_app, (uint64)sizeof(uint32))
        || total_size >= UINT32_MAX
        || !validate_native_addr((void *)si_data, total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_ciovec_t) * (uint64)si_data_len;
    if (total_size >= UINT32_MAX
        || !(ciovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    ciovec = ciovec_begin;
    for (i = 0; i < si_data_len; i++, si_data++, ciovec++) {
        if (!validate_app_addr((uint64)si_data->buf_offset,
                               (uint64)si_data->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        ciovec->buf = (char *)addr_app_to_native((uint64)si_data->buf_offset);
        ciovec->buf_len = si_data->buf_len;
    }

    err = uvwasi_sock_send(uvwasi, sock, ciovec_begin, si_data_len, si_flags,
                           &so_datalen);
    if (err)
        goto fail;

    *so_datalen_app = (uint32)so_datalen;

    /* success */
    err = 0;

fail:
    wasm_runtime_free(ciovec_begin);
    return err;
}

static wasi_errno_t
wasi_sock_shutdown(wasm_exec_env_t exec_env, wasi_fd_t sock, wasi_sdflags_t how)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    if (!uvwasi)
        return (wasi_errno_t)-1;

    return uvwasi_sock_shutdown(uvwasi, sock, how);
}

static wasi_errno_t
wasi_sched_yield(wasm_exec_env_t exec_env)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uvwasi_t *uvwasi = get_wasi_ctx(module_inst);

    return uvwasi_sched_yield(uvwasi);
}

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, wasi_##func_name, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_libc_wasi[] = {
    REG_NATIVE_FUNC(args_get, "(**)i"),
    REG_NATIVE_FUNC(args_sizes_get, "(**)i"),
    REG_NATIVE_FUNC(clock_res_get, "(i*)i"),
    REG_NATIVE_FUNC(clock_time_get, "(iI*)i"),
    REG_NATIVE_FUNC(environ_get, "(**)i"),
    REG_NATIVE_FUNC(environ_sizes_get, "(**)i"),
    REG_NATIVE_FUNC(fd_prestat_get, "(i*)i"),
    REG_NATIVE_FUNC(fd_prestat_dir_name, "(i*~)i"),
    REG_NATIVE_FUNC(fd_close, "(i)i"),
    REG_NATIVE_FUNC(fd_datasync, "(i)i"),
    REG_NATIVE_FUNC(fd_pread, "(i*iI*)i"),
    REG_NATIVE_FUNC(fd_pwrite, "(i*iI*)i"),
    REG_NATIVE_FUNC(fd_read, "(i*i*)i"),
    REG_NATIVE_FUNC(fd_renumber, "(ii)i"),
    REG_NATIVE_FUNC(fd_seek, "(iIi*)i"),
    REG_NATIVE_FUNC(fd_tell, "(i*)i"),
    REG_NATIVE_FUNC(fd_fdstat_get, "(i*)i"),
    REG_NATIVE_FUNC(fd_fdstat_set_flags, "(ii)i"),
    REG_NATIVE_FUNC(fd_fdstat_set_rights, "(iII)i"),
    REG_NATIVE_FUNC(fd_sync, "(i)i"),
    REG_NATIVE_FUNC(fd_write, "(i*i*)i"),
    REG_NATIVE_FUNC(fd_advise, "(iIIi)i"),
    REG_NATIVE_FUNC(fd_allocate, "(iII)i"),
    REG_NATIVE_FUNC(path_create_directory, "(i*~)i"),
    REG_NATIVE_FUNC(path_link, "(ii*~i*~)i"),
    REG_NATIVE_FUNC(path_open, "(ii*~iIIi*)i"),
    REG_NATIVE_FUNC(fd_readdir, "(i*~I*)i"),
    REG_NATIVE_FUNC(path_readlink, "(i*~*~*)i"),
    REG_NATIVE_FUNC(path_rename, "(i*~i*~)i"),
    REG_NATIVE_FUNC(fd_filestat_get, "(i*)i"),
    REG_NATIVE_FUNC(fd_filestat_set_times, "(iIIi)i"),
    REG_NATIVE_FUNC(fd_filestat_set_size, "(iI)i"),
    REG_NATIVE_FUNC(path_filestat_get, "(ii*~*)i"),
    REG_NATIVE_FUNC(path_filestat_set_times, "(ii*~IIi)i"),
    REG_NATIVE_FUNC(path_symlink, "(*~i*~)i"),
    REG_NATIVE_FUNC(path_unlink_file, "(i*~)i"),
    REG_NATIVE_FUNC(path_remove_directory, "(i*~)i"),
    REG_NATIVE_FUNC(poll_oneoff, "(**i*)i"),
    REG_NATIVE_FUNC(proc_exit, "(i)"),
    REG_NATIVE_FUNC(proc_raise, "(i)i"),
    REG_NATIVE_FUNC(random_get, "(*~)i"),
    REG_NATIVE_FUNC(sock_recv, "(i*ii**)i"),
    REG_NATIVE_FUNC(sock_send, "(i*ii*)i"),
    REG_NATIVE_FUNC(sock_shutdown, "(ii)i"),
    REG_NATIVE_FUNC(sched_yield, "()i"),
};

uint32
get_libc_wasi_export_apis(NativeSymbol **p_libc_wasi_apis)
{
    *p_libc_wasi_apis = native_symbols_libc_wasi;
    return sizeof(native_symbols_libc_wasi) / sizeof(NativeSymbol);
}
