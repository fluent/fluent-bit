/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "libc_wasi_wrapper.h"
#include "bh_platform.h"
#include "wasm_export.h"

void
wasm_runtime_set_exception(wasm_module_inst_t module, const char *exception);

/* clang-format off */
#define get_module_inst(exec_env) \
    wasm_runtime_get_module_inst(exec_env)

#define get_wasi_ctx(module_inst) \
    wasm_runtime_get_wasi_ctx(module_inst)

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

typedef struct wasi_prestat_app {
    wasi_preopentype_t pr_type;
    uint32 pr_name_len;
} wasi_prestat_app_t;

typedef struct iovec_app {
    uint32 buf_offset;
    uint32 buf_len;
} iovec_app_t;

typedef struct WASIContext {
    struct fd_table *curfds;
    struct fd_prestats *prestats;
    struct argv_environ_values *argv_environ;
    struct addr_pool *addr_pool;
    char *ns_lookup_buf;
    char **ns_lookup_list;
    char *argv_buf;
    char **argv_list;
    char *env_buf;
    char **env_list;
} * wasi_ctx_t;

wasi_ctx_t
wasm_runtime_get_wasi_ctx(wasm_module_inst_t module_inst);

static inline struct fd_table *
wasi_ctx_get_curfds(wasm_module_inst_t module_inst, wasi_ctx_t wasi_ctx)
{
    if (!wasi_ctx)
        return NULL;
    return wasi_ctx->curfds;
}

static inline struct argv_environ_values *
wasi_ctx_get_argv_environ(wasm_module_inst_t module_inst, wasi_ctx_t wasi_ctx)
{
    if (!wasi_ctx)
        return NULL;
    return wasi_ctx->argv_environ;
}

static inline struct fd_prestats *
wasi_ctx_get_prestats(wasm_module_inst_t module_inst, wasi_ctx_t wasi_ctx)
{
    if (!wasi_ctx)
        return NULL;
    return wasi_ctx->prestats;
}

static inline struct addr_pool *
wasi_ctx_get_addr_pool(wasm_module_inst_t module_inst, wasi_ctx_t wasi_ctx)
{
    if (!wasi_ctx)
        return NULL;
    return wasi_ctx->addr_pool;
}

static inline char **
wasi_ctx_get_ns_lookup_list(wasi_ctx_t wasi_ctx)
{
    if (!wasi_ctx)
        return NULL;
    return wasi_ctx->ns_lookup_list;
}

static wasi_errno_t
wasi_args_get(wasm_exec_env_t exec_env, uint32 *argv_offsets, char *argv_buf)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct argv_environ_values *argv_environ =
        wasi_ctx_get_argv_environ(module_inst, wasi_ctx);
    size_t argc, argv_buf_size, i;
    char **argv;
    uint64 total_size;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_args_sizes_get(argv_environ, &argc, &argv_buf_size);
    if (err)
        return err;

    total_size = sizeof(int32) * ((uint64)argc + 1);
    if (total_size >= UINT32_MAX
        || !validate_native_addr(argv_offsets, (uint32)total_size)
        || argv_buf_size >= UINT32_MAX
        || !validate_native_addr(argv_buf, (uint32)argv_buf_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(char *) * ((uint64)argc + 1);
    if (total_size >= UINT32_MAX
        || !(argv = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_args_get(argv_environ, argv, argv_buf);
    if (err) {
        wasm_runtime_free(argv);
        return err;
    }

    for (i = 0; i < argc; i++)
        argv_offsets[i] = addr_native_to_app(argv[i]);

    wasm_runtime_free(argv);
    return 0;
}

static wasi_errno_t
wasi_args_sizes_get(wasm_exec_env_t exec_env, uint32 *argc_app,
                    uint32 *argv_buf_size_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct argv_environ_values *argv_environ;
    size_t argc, argv_buf_size;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(argc_app, sizeof(uint32))
        || !validate_native_addr(argv_buf_size_app, sizeof(uint32)))
        return (wasi_errno_t)-1;

    argv_environ = wasi_ctx->argv_environ;

    err = wasmtime_ssp_args_sizes_get(argv_environ, &argc, &argv_buf_size);
    if (err)
        return err;

    *argc_app = (uint32)argc;
    *argv_buf_size_app = (uint32)argv_buf_size;
    return 0;
}

static wasi_errno_t
wasi_clock_res_get(wasm_exec_env_t exec_env,
                   wasi_clockid_t clock_id, /* uint32 clock_id */
                   wasi_timestamp_t *resolution /* uint64 *resolution */)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (!validate_native_addr(resolution, sizeof(wasi_timestamp_t)))
        return (wasi_errno_t)-1;

    return wasmtime_ssp_clock_res_get(clock_id, resolution);
}

static wasi_errno_t
wasi_clock_time_get(wasm_exec_env_t exec_env,
                    wasi_clockid_t clock_id,    /* uint32 clock_id */
                    wasi_timestamp_t precision, /* uint64 precision */
                    wasi_timestamp_t *time /* uint64 *time */)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (!validate_native_addr(time, sizeof(wasi_timestamp_t)))
        return (wasi_errno_t)-1;

    return wasmtime_ssp_clock_time_get(clock_id, precision, time);
}

static wasi_errno_t
wasi_environ_get(wasm_exec_env_t exec_env, uint32 *environ_offsets,
                 char *environ_buf)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct argv_environ_values *argv_environ =
        wasi_ctx_get_argv_environ(module_inst, wasi_ctx);
    size_t environ_count, environ_buf_size, i;
    uint64 total_size;
    char **environs;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_environ_sizes_get(argv_environ, &environ_count,
                                         &environ_buf_size);
    if (err)
        return err;

    total_size = sizeof(int32) * ((uint64)environ_count + 1);
    if (total_size >= UINT32_MAX
        || !validate_native_addr(environ_offsets, (uint32)total_size)
        || environ_buf_size >= UINT32_MAX
        || !validate_native_addr(environ_buf, (uint32)environ_buf_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(char *) * (((uint64)environ_count + 1));

    if (total_size >= UINT32_MAX
        || !(environs = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_environ_get(argv_environ, environs, environ_buf);
    if (err) {
        wasm_runtime_free(environs);
        return err;
    }

    for (i = 0; i < environ_count; i++)
        environ_offsets[i] = addr_native_to_app(environs[i]);

    wasm_runtime_free(environs);
    return 0;
}

static wasi_errno_t
wasi_environ_sizes_get(wasm_exec_env_t exec_env, uint32 *environ_count_app,
                       uint32 *environ_buf_size_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct argv_environ_values *argv_environ =
        wasi_ctx_get_argv_environ(module_inst, wasi_ctx);
    size_t environ_count, environ_buf_size;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(environ_count_app, sizeof(uint32))
        || !validate_native_addr(environ_buf_size_app, sizeof(uint32)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_environ_sizes_get(argv_environ, &environ_count,
                                         &environ_buf_size);
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
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_prestats *prestats = wasi_ctx_get_prestats(module_inst, wasi_ctx);
    wasi_prestat_t prestat;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(prestat_app, sizeof(wasi_prestat_app_t)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_fd_prestat_get(prestats, fd, &prestat);
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
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_prestats *prestats = wasi_ctx_get_prestats(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_prestat_dir_name(prestats, fd, path, path_len);
}

static wasi_errno_t
wasi_fd_close(wasm_exec_env_t exec_env, wasi_fd_t fd)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    struct fd_prestats *prestats = wasi_ctx_get_prestats(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_close(curfds, prestats, fd);
}

static wasi_errno_t
wasi_fd_datasync(wasm_exec_env_t exec_env, wasi_fd_t fd)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_datasync(curfds, fd);
}

static wasi_errno_t
wasi_fd_pread(wasm_exec_env_t exec_env, wasi_fd_t fd, iovec_app_t *iovec_app,
              uint32 iovs_len, wasi_filesize_t offset, uint32 *nread_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    wasi_iovec_t *iovec, *iovec_begin;
    uint64 total_size;
    size_t nread;
    uint32 i;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)iovs_len;
    if (!validate_native_addr(nread_app, (uint32)sizeof(uint32))
        || total_size >= UINT32_MAX
        || !validate_native_addr(iovec_app, (uint32)total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_iovec_t) * (uint64)iovs_len;
    if (total_size >= UINT32_MAX
        || !(iovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    iovec = iovec_begin;

    for (i = 0; i < iovs_len; i++, iovec_app++, iovec++) {
        if (!validate_app_addr(iovec_app->buf_offset, iovec_app->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        iovec->buf = (void *)addr_app_to_native(iovec_app->buf_offset);
        iovec->buf_len = iovec_app->buf_len;
    }

    err = wasmtime_ssp_fd_pread(curfds, fd, iovec_begin, iovs_len, offset,
                                &nread);
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
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    wasi_ciovec_t *ciovec, *ciovec_begin;
    uint64 total_size;
    size_t nwritten;
    uint32 i;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)iovs_len;
    if (!validate_native_addr(nwritten_app, (uint32)sizeof(uint32))
        || total_size >= UINT32_MAX
        || !validate_native_addr((void *)iovec_app, (uint32)total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_ciovec_t) * (uint64)iovs_len;
    if (total_size >= UINT32_MAX
        || !(ciovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    ciovec = ciovec_begin;

    for (i = 0; i < iovs_len; i++, iovec_app++, ciovec++) {
        if (!validate_app_addr(iovec_app->buf_offset, iovec_app->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        ciovec->buf = (char *)addr_app_to_native(iovec_app->buf_offset);
        ciovec->buf_len = iovec_app->buf_len;
    }

    err = wasmtime_ssp_fd_pwrite(curfds, fd, ciovec_begin, iovs_len, offset,
                                 &nwritten);
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
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    wasi_iovec_t *iovec, *iovec_begin;
    uint64 total_size;
    size_t nread;
    uint32 i;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)iovs_len;
    if (!validate_native_addr(nread_app, (uint32)sizeof(uint32))
        || total_size >= UINT32_MAX
        || !validate_native_addr((void *)iovec_app, (uint32)total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_iovec_t) * (uint64)iovs_len;
    if (total_size >= UINT32_MAX
        || !(iovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    iovec = iovec_begin;

    for (i = 0; i < iovs_len; i++, iovec_app++, iovec++) {
        if (!validate_app_addr(iovec_app->buf_offset, iovec_app->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        iovec->buf = (void *)addr_app_to_native(iovec_app->buf_offset);
        iovec->buf_len = iovec_app->buf_len;
    }

    err = wasmtime_ssp_fd_read(curfds, fd, iovec_begin, iovs_len, &nread);
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
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    struct fd_prestats *prestats = wasi_ctx_get_prestats(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_renumber(curfds, prestats, from, to);
}

static wasi_errno_t
wasi_fd_seek(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_filedelta_t offset,
             wasi_whence_t whence, wasi_filesize_t *newoffset)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(newoffset, sizeof(wasi_filesize_t)))
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_seek(curfds, fd, offset, whence, newoffset);
}

static wasi_errno_t
wasi_fd_tell(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_filesize_t *newoffset)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(newoffset, sizeof(wasi_filesize_t)))
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_tell(curfds, fd, newoffset);
}

static wasi_errno_t
wasi_fd_fdstat_get(wasm_exec_env_t exec_env, wasi_fd_t fd,
                   wasi_fdstat_t *fdstat_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    wasi_fdstat_t fdstat;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(fdstat_app, sizeof(wasi_fdstat_t)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_fd_fdstat_get(curfds, fd, &fdstat);
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
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_fdstat_set_flags(curfds, fd, flags);
}

static wasi_errno_t
wasi_fd_fdstat_set_rights(wasm_exec_env_t exec_env, wasi_fd_t fd,
                          wasi_rights_t fs_rights_base,
                          wasi_rights_t fs_rights_inheriting)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_fdstat_set_rights(curfds, fd, fs_rights_base,
                                             fs_rights_inheriting);
}

static wasi_errno_t
wasi_fd_sync(wasm_exec_env_t exec_env, wasi_fd_t fd)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_sync(curfds, fd);
}

static wasi_errno_t
wasi_fd_write(wasm_exec_env_t exec_env, wasi_fd_t fd,
              const iovec_app_t *iovec_app, uint32 iovs_len,
              uint32 *nwritten_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    wasi_ciovec_t *ciovec, *ciovec_begin;
    uint64 total_size;
    size_t nwritten;
    uint32 i;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    total_size = sizeof(iovec_app_t) * (uint64)iovs_len;
    if (!validate_native_addr(nwritten_app, (uint32)sizeof(uint32))
        || total_size >= UINT32_MAX
        || !validate_native_addr((void *)iovec_app, (uint32)total_size))
        return (wasi_errno_t)-1;

    total_size = sizeof(wasi_ciovec_t) * (uint64)iovs_len;
    if (total_size >= UINT32_MAX
        || !(ciovec_begin = wasm_runtime_malloc((uint32)total_size)))
        return (wasi_errno_t)-1;

    ciovec = ciovec_begin;

    for (i = 0; i < iovs_len; i++, iovec_app++, ciovec++) {
        if (!validate_app_addr(iovec_app->buf_offset, iovec_app->buf_len)) {
            err = (wasi_errno_t)-1;
            goto fail;
        }
        ciovec->buf = (char *)addr_app_to_native(iovec_app->buf_offset);
        ciovec->buf_len = iovec_app->buf_len;
    }

    err = wasmtime_ssp_fd_write(curfds, fd, ciovec_begin, iovs_len, &nwritten);
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
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_advise(curfds, fd, offset, len, advice);
}

static wasi_errno_t
wasi_fd_allocate(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_filesize_t offset,
                 wasi_filesize_t len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_allocate(curfds, fd, offset, len);
}

static wasi_errno_t
wasi_path_create_directory(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           const char *path, uint32 path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_path_create_directory(curfds, fd, path, path_len);
}

static wasi_errno_t
wasi_path_link(wasm_exec_env_t exec_env, wasi_fd_t old_fd,
               wasi_lookupflags_t old_flags, const char *old_path,
               uint32 old_path_len, wasi_fd_t new_fd, const char *new_path,
               uint32 new_path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    struct fd_prestats *prestats = wasi_ctx_get_prestats(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_path_link(curfds, prestats, old_fd, old_flags, old_path,
                                  old_path_len, new_fd, new_path, new_path_len);
}

static wasi_errno_t
wasi_path_open(wasm_exec_env_t exec_env, wasi_fd_t dirfd,
               wasi_lookupflags_t dirflags, const char *path, uint32 path_len,
               wasi_oflags_t oflags, wasi_rights_t fs_rights_base,
               wasi_rights_t fs_rights_inheriting, wasi_fdflags_t fs_flags,
               wasi_fd_t *fd_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    wasi_fd_t fd = (wasi_fd_t)-1; /* set fd_app -1 if path open failed */
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(fd_app, sizeof(wasi_fd_t)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_path_open(curfds, dirfd, dirflags, path, path_len,
                                 oflags, fs_rights_base, fs_rights_inheriting,
                                 fs_flags, &fd);

    *fd_app = fd;
    return err;
}

static wasi_errno_t
wasi_fd_readdir(wasm_exec_env_t exec_env, wasi_fd_t fd, void *buf,
                uint32 buf_len, wasi_dircookie_t cookie, uint32 *bufused_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    size_t bufused;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(bufused_app, sizeof(uint32)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_fd_readdir(curfds, fd, buf, buf_len, cookie, &bufused);
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
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    size_t bufused;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(bufused_app, sizeof(uint32)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_path_readlink(curfds, fd, path, path_len, buf, buf_len,
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
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_path_rename(curfds, old_fd, old_path, old_path_len,
                                    new_fd, new_path, new_path_len);
}

static wasi_errno_t
wasi_fd_filestat_get(wasm_exec_env_t exec_env, wasi_fd_t fd,
                     wasi_filestat_t *filestat)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(filestat, sizeof(wasi_filestat_t)))
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_filestat_get(curfds, fd, filestat);
}

static wasi_errno_t
wasi_fd_filestat_set_times(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           wasi_timestamp_t st_atim, wasi_timestamp_t st_mtim,
                           wasi_fstflags_t fstflags)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_filestat_set_times(curfds, fd, st_atim, st_mtim,
                                              fstflags);
}

static wasi_errno_t
wasi_fd_filestat_set_size(wasm_exec_env_t exec_env, wasi_fd_t fd,
                          wasi_filesize_t st_size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_fd_filestat_set_size(curfds, fd, st_size);
}

static wasi_errno_t
wasi_path_filestat_get(wasm_exec_env_t exec_env, wasi_fd_t fd,
                       wasi_lookupflags_t flags, const char *path,
                       uint32 path_len, wasi_filestat_t *filestat)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr(filestat, sizeof(wasi_filestat_t)))
        return (wasi_errno_t)-1;

    return wasmtime_ssp_path_filestat_get(curfds, fd, flags, path, path_len,
                                          filestat);
}

static wasi_errno_t
wasi_path_filestat_set_times(wasm_exec_env_t exec_env, wasi_fd_t fd,
                             wasi_lookupflags_t flags, const char *path,
                             uint32 path_len, wasi_timestamp_t st_atim,
                             wasi_timestamp_t st_mtim, wasi_fstflags_t fstflags)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_path_filestat_set_times(
        curfds, fd, flags, path, path_len, st_atim, st_mtim, fstflags);
}

static wasi_errno_t
wasi_path_symlink(wasm_exec_env_t exec_env, const char *old_path,
                  uint32 old_path_len, wasi_fd_t fd, const char *new_path,
                  uint32 new_path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    struct fd_prestats *prestats = wasi_ctx_get_prestats(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_path_symlink(curfds, prestats, old_path, old_path_len,
                                     fd, new_path, new_path_len);
}

static wasi_errno_t
wasi_path_unlink_file(wasm_exec_env_t exec_env, wasi_fd_t fd, const char *path,
                      uint32 path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_path_unlink_file(curfds, fd, path, path_len);
}

static wasi_errno_t
wasi_path_remove_directory(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           const char *path, uint32 path_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    return wasmtime_ssp_path_remove_directory(curfds, fd, path, path_len);
}

static wasi_errno_t
wasi_poll_oneoff(wasm_exec_env_t exec_env, const wasi_subscription_t *in,
                 wasi_event_t *out, uint32 nsubscriptions, uint32 *nevents_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    size_t nevents;
    wasi_errno_t err;

    if (!wasi_ctx)
        return (wasi_errno_t)-1;

    if (!validate_native_addr((void *)in, sizeof(wasi_subscription_t))
        || !validate_native_addr(out, sizeof(wasi_event_t))
        || !validate_native_addr(nevents_app, sizeof(uint32)))
        return (wasi_errno_t)-1;

    err = wasmtime_ssp_poll_oneoff(curfds, in, out, nsubscriptions, &nevents);
    if (err)
        return err;

    *nevents_app = (uint32)nevents;
    return 0;
}

static void
wasi_proc_exit(wasm_exec_env_t exec_env, wasi_exitcode_t rval)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    /* Here throwing exception is just to let wasm app exit,
       the upper layer should clear the exception and return
       as normal */
    wasm_runtime_set_exception(module_inst, "wasi proc exit");
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
    return wasmtime_ssp_random_get(buf, buf_len);
}

static wasi_errno_t
wasi_sock_accept(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_fdflags_t flags,
                 wasi_fd_t *fd_new)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasi_ssp_sock_accept(curfds, fd, flags, fd_new);
}

static wasi_errno_t
wasi_sock_addr_local(wasm_exec_env_t exec_env, wasi_fd_t fd,
                     __wasi_addr_t *addr)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(addr, sizeof(__wasi_addr_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasi_ssp_sock_addr_local(curfds, fd, addr);
}

static wasi_errno_t
wasi_sock_addr_remote(wasm_exec_env_t exec_env, wasi_fd_t fd,
                      __wasi_addr_t *addr)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(addr, sizeof(__wasi_addr_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasi_ssp_sock_addr_remote(curfds, fd, addr);
}

static wasi_errno_t
wasi_sock_addr_resolve(wasm_exec_env_t exec_env, const char *host,
                       const char *service, __wasi_addr_info_hints_t *hints,
                       __wasi_addr_info_t *addr_info,
                       __wasi_size_t addr_info_size,
                       __wasi_size_t *max_info_size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;
    char **ns_lookup_list = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    ns_lookup_list = wasi_ctx_get_ns_lookup_list(wasi_ctx);

    return wasi_ssp_sock_addr_resolve(curfds, ns_lookup_list, host, service,
                                      hints, addr_info, addr_info_size,
                                      max_info_size);
}

static wasi_errno_t
wasi_sock_bind(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_addr_t *addr)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;
    struct addr_pool *addr_pool = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    addr_pool = wasi_ctx_get_addr_pool(module_inst, wasi_ctx);

    return wasi_ssp_sock_bind(curfds, addr_pool, fd, addr);
}

static wasi_errno_t
wasi_sock_close(wasm_exec_env_t exec_env, wasi_fd_t fd)
{
    return __WASI_ENOSYS;
}

static wasi_errno_t
wasi_sock_connect(wasm_exec_env_t exec_env, wasi_fd_t fd, wasi_addr_t *addr)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;
    struct addr_pool *addr_pool = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    addr_pool = wasi_ctx_get_addr_pool(module_inst, wasi_ctx);

    return wasi_ssp_sock_connect(curfds, addr_pool, fd, addr);
}

static wasi_errno_t
wasi_sock_get_broadcast(wasm_exec_env_t exec_env, wasi_fd_t fd,
                        bool *is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(is_enabled, sizeof(bool)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_broadcast(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_get_keep_alive(wasm_exec_env_t exec_env, wasi_fd_t fd,
                         bool *is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(is_enabled, sizeof(bool)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_keep_alive(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_get_linger(wasm_exec_env_t exec_env, wasi_fd_t fd, bool *is_enabled,
                     int *linger_s)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(is_enabled, sizeof(bool))
        || !validate_native_addr(linger_s, sizeof(int)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_linger(curfds, fd, is_enabled, linger_s);
}

static wasi_errno_t
wasi_sock_get_recv_buf_size(wasm_exec_env_t exec_env, wasi_fd_t fd,
                            size_t *size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(size, sizeof(wasi_size_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_recv_buf_size(curfds, fd, size);
}

static wasi_errno_t
wasi_sock_get_recv_timeout(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           uint64_t *timeout_us)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(timeout_us, sizeof(uint64_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_recv_timeout(curfds, fd, timeout_us);
}

static wasi_errno_t
wasi_sock_get_reuse_addr(wasm_exec_env_t exec_env, wasi_fd_t fd,
                         bool *is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(is_enabled, sizeof(bool)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_reuse_addr(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_get_reuse_port(wasm_exec_env_t exec_env, wasi_fd_t fd,
                         bool *is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(is_enabled, sizeof(bool)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_reuse_port(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_get_send_buf_size(wasm_exec_env_t exec_env, wasi_fd_t fd,
                            size_t *size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(size, sizeof(__wasi_size_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_send_buf_size(curfds, fd, size);
}

static wasi_errno_t
wasi_sock_get_send_timeout(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           uint64_t *timeout_us)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(timeout_us, sizeof(uint64_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_send_timeout(curfds, fd, timeout_us);
}

static wasi_errno_t
wasi_sock_get_tcp_fastopen_connect(wasm_exec_env_t exec_env, wasi_fd_t fd,
                                   bool *is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(is_enabled, sizeof(bool)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_tcp_fastopen_connect(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_get_tcp_no_delay(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           bool *is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(is_enabled, sizeof(bool)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_tcp_no_delay(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_get_tcp_quick_ack(wasm_exec_env_t exec_env, wasi_fd_t fd,
                            bool *is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(is_enabled, sizeof(bool)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_tcp_quick_ack(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_get_tcp_keep_idle(wasm_exec_env_t exec_env, wasi_fd_t fd,
                            uint32_t *time_s)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(time_s, sizeof(uint32_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_tcp_keep_idle(curfds, fd, time_s);
}

static wasi_errno_t
wasi_sock_get_tcp_keep_intvl(wasm_exec_env_t exec_env, wasi_fd_t fd,
                             uint32_t *time_s)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(time_s, sizeof(uint32_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_tcp_keep_intvl(curfds, fd, time_s);
}

static wasi_errno_t
wasi_sock_get_ip_multicast_loop(wasm_exec_env_t exec_env, wasi_fd_t fd,
                                bool ipv6, bool *is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(is_enabled, sizeof(bool)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_ip_multicast_loop(curfds, fd, ipv6,
                                                   is_enabled);
}

static wasi_errno_t
wasi_sock_get_ip_ttl(wasm_exec_env_t exec_env, wasi_fd_t fd, uint8_t *ttl_s)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(ttl_s, sizeof(uint8_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_ip_ttl(curfds, fd, ttl_s);
}

static wasi_errno_t
wasi_sock_get_ip_multicast_ttl(wasm_exec_env_t exec_env, wasi_fd_t fd,
                               uint8_t *ttl_s)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(ttl_s, sizeof(uint8_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_ip_multicast_ttl(curfds, fd, ttl_s);
}

static wasi_errno_t
wasi_sock_get_ipv6_only(wasm_exec_env_t exec_env, wasi_fd_t fd,
                        bool *is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(is_enabled, sizeof(bool)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_get_ipv6_only(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_listen(wasm_exec_env_t exec_env, wasi_fd_t fd, uint32 backlog)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasi_ssp_sock_listen(curfds, fd, backlog);
}

static wasi_errno_t
wasi_sock_open(wasm_exec_env_t exec_env, wasi_fd_t poolfd,
               wasi_address_family_t af, wasi_sock_type_t socktype,
               wasi_fd_t *sockfd)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasi_ssp_sock_open(curfds, poolfd, af, socktype, sockfd);
}

static wasi_errno_t
wasi_sock_set_broadcast(wasm_exec_env_t exec_env, wasi_fd_t fd, bool is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_broadcast(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_set_keep_alive(wasm_exec_env_t exec_env, wasi_fd_t fd,
                         bool is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_keep_alive(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_set_linger(wasm_exec_env_t exec_env, wasi_fd_t fd, bool is_enabled,
                     int linger_s)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_linger(curfds, fd, is_enabled, linger_s);
}

static wasi_errno_t
wasi_sock_set_recv_buf_size(wasm_exec_env_t exec_env, wasi_fd_t fd, size_t size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_recv_buf_size(curfds, fd, size);
}

static wasi_errno_t
wasi_sock_set_recv_timeout(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           uint64_t timeout_us)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_recv_timeout(curfds, fd, timeout_us);
}

static wasi_errno_t
wasi_sock_set_reuse_addr(wasm_exec_env_t exec_env, wasi_fd_t fd,
                         bool is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_reuse_addr(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_set_reuse_port(wasm_exec_env_t exec_env, wasi_fd_t fd,
                         bool is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_reuse_port(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_set_send_buf_size(wasm_exec_env_t exec_env, wasi_fd_t fd, size_t size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_send_buf_size(curfds, fd, size);
}

static wasi_errno_t
wasi_sock_set_send_timeout(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           uint64_t timeout_us)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_send_timeout(curfds, fd, timeout_us);
}

static wasi_errno_t
wasi_sock_set_tcp_fastopen_connect(wasm_exec_env_t exec_env, wasi_fd_t fd,
                                   bool is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_tcp_fastopen_connect(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_set_tcp_no_delay(wasm_exec_env_t exec_env, wasi_fd_t fd,
                           bool is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_tcp_no_delay(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_set_tcp_quick_ack(wasm_exec_env_t exec_env, wasi_fd_t fd,
                            bool is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_tcp_quick_ack(curfds, fd, is_enabled);
}

static wasi_errno_t
wasi_sock_set_tcp_keep_idle(wasm_exec_env_t exec_env, wasi_fd_t fd,
                            uint32_t time_s)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_tcp_keep_idle(curfds, fd, time_s);
}

static wasi_errno_t
wasi_sock_set_tcp_keep_intvl(wasm_exec_env_t exec_env, wasi_fd_t fd,
                             uint32_t time_s)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_tcp_keep_intvl(curfds, fd, time_s);
}

static wasi_errno_t
wasi_sock_set_ip_multicast_loop(wasm_exec_env_t exec_env, wasi_fd_t fd,
                                bool ipv6, bool is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_ip_multicast_loop(curfds, fd, ipv6,
                                                   is_enabled);
}

static wasi_errno_t
wasi_sock_set_ip_add_membership(wasm_exec_env_t exec_env, wasi_fd_t fd,
                                __wasi_addr_ip_t *imr_multiaddr,
                                uint32_t imr_interface)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(imr_multiaddr, sizeof(__wasi_addr_ip_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_ip_add_membership(curfds, fd, imr_multiaddr,
                                                   imr_interface);
}

static wasi_errno_t
wasi_sock_set_ip_drop_membership(wasm_exec_env_t exec_env, wasi_fd_t fd,
                                 __wasi_addr_ip_t *imr_multiaddr,
                                 uint32_t imr_interface)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    if (!validate_native_addr(imr_multiaddr, sizeof(__wasi_addr_ip_t)))
        return __WASI_EINVAL;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_ip_drop_membership(curfds, fd, imr_multiaddr,
                                                    imr_interface);
}

static wasi_errno_t
wasi_sock_set_ip_ttl(wasm_exec_env_t exec_env, wasi_fd_t fd, uint8_t ttl_s)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_ip_ttl(curfds, fd, ttl_s);
}

static wasi_errno_t
wasi_sock_set_ip_multicast_ttl(wasm_exec_env_t exec_env, wasi_fd_t fd,
                               uint8_t ttl_s)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_ip_multicast_ttl(curfds, fd, ttl_s);
}

static wasi_errno_t
wasi_sock_set_ipv6_only(wasm_exec_env_t exec_env, wasi_fd_t fd, bool is_enabled)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = NULL;

    if (!wasi_ctx)
        return __WASI_EACCES;

    curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    return wasmtime_ssp_sock_set_ipv6_only(curfds, fd, is_enabled);
}

static wasi_errno_t
allocate_iovec_app_buffer(wasm_module_inst_t module_inst,
                          const iovec_app_t *data, uint32 data_len,
                          uint8 **buf_ptr, uint64 *buf_len)
{
    uint64 total_size = 0;
    uint32 i;
    uint8 *buf_begin = NULL;

    if (data_len == 0) {
        return __WASI_EINVAL;
    }

    total_size = sizeof(iovec_app_t) * (uint64)data_len;
    if (total_size >= UINT32_MAX
        || !validate_native_addr((void *)data, (uint32)total_size))
        return __WASI_EINVAL;

    for (total_size = 0, i = 0; i < data_len; i++, data++) {
        total_size += data->buf_len;
    }

    if (total_size == 0) {
        return __WASI_EINVAL;
    }

    if (total_size >= UINT32_MAX
        || !(buf_begin = wasm_runtime_malloc((uint32)total_size))) {
        return __WASI_ENOMEM;
    }

    *buf_len = total_size;
    *buf_ptr = buf_begin;

    return __WASI_ESUCCESS;
}

static inline size_t
min(size_t a, size_t b)
{
    return a > b ? b : a;
}

static wasi_errno_t
copy_buffer_to_iovec_app(wasm_module_inst_t module_inst, uint8 *buf_begin,
                         uint32 buf_size, iovec_app_t *data, uint32 data_len,
                         uint32 size_to_copy)
{
    uint8 *buf = buf_begin;
    uint32 i;
    uint32 size_to_copy_into_iovec;

    if (buf_size < size_to_copy) {
        return __WASI_EINVAL;
    }

    for (i = 0; i < data_len; data++, i++) {
        char *native_addr;

        if (!validate_app_addr(data->buf_offset, data->buf_len)) {
            return __WASI_EINVAL;
        }

        if (buf >= buf_begin + buf_size
            || buf + data->buf_len < buf /* integer overflow */
            || buf + data->buf_len > buf_begin + buf_size
            || size_to_copy == 0) {
            break;
        }

        /**
         * If our app buffer size is smaller than the amount to be copied,
         * only copy the amount in the app buffer. Otherwise, we fill the iovec
         * buffer and reduce size to copy on the next iteration
         */
        size_to_copy_into_iovec = min(data->buf_len, size_to_copy);

        native_addr = (void *)addr_app_to_native(data->buf_offset);
        bh_memcpy_s(native_addr, size_to_copy_into_iovec, buf,
                    size_to_copy_into_iovec);
        buf += size_to_copy_into_iovec;
        size_to_copy -= size_to_copy_into_iovec;
    }

    return __WASI_ESUCCESS;
}

static wasi_errno_t
wasi_sock_recv_from(wasm_exec_env_t exec_env, wasi_fd_t sock,
                    iovec_app_t *ri_data, uint32 ri_data_len,
                    wasi_riflags_t ri_flags, __wasi_addr_t *src_addr,
                    uint32 *ro_data_len)
{
    /**
     * ri_data_len is the length of a list of iovec_app_t, which head is
     * ri_data. ro_data_len is the number of bytes received
     **/
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    uint64 total_size;
    uint8 *buf_begin = NULL;
    wasi_errno_t err;
    size_t recv_bytes = 0;

    if (!wasi_ctx) {
        return __WASI_EINVAL;
    }

    if (!validate_native_addr(ro_data_len, (uint32)sizeof(uint32)))
        return __WASI_EINVAL;

    err = allocate_iovec_app_buffer(module_inst, ri_data, ri_data_len,
                                    &buf_begin, &total_size);
    if (err != __WASI_ESUCCESS) {
        goto fail;
    }

    memset(buf_begin, 0, total_size);

    *ro_data_len = 0;
    err = wasmtime_ssp_sock_recv_from(curfds, sock, buf_begin, total_size,
                                      ri_flags, src_addr, &recv_bytes);
    if (err != __WASI_ESUCCESS) {
        goto fail;
    }
    *ro_data_len = (uint32)recv_bytes;

    err = copy_buffer_to_iovec_app(module_inst, buf_begin, (uint32)total_size,
                                   ri_data, ri_data_len, (uint32)recv_bytes);

fail:
    if (buf_begin) {
        wasm_runtime_free(buf_begin);
    }
    return err;
}

static wasi_errno_t
wasi_sock_recv(wasm_exec_env_t exec_env, wasi_fd_t sock, iovec_app_t *ri_data,
               uint32 ri_data_len, wasi_riflags_t ri_flags, uint32 *ro_data_len,
               wasi_roflags_t *ro_flags)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    __wasi_addr_t src_addr;
    wasi_errno_t error;

    if (!validate_native_addr(ro_flags, (uint32)sizeof(wasi_roflags_t)))
        return __WASI_EINVAL;

    error = wasi_sock_recv_from(exec_env, sock, ri_data, ri_data_len, ri_flags,
                                &src_addr, ro_data_len);
    *ro_flags = ri_flags;

    return error;
}

static wasi_errno_t
convert_iovec_app_to_buffer(wasm_module_inst_t module_inst,
                            const iovec_app_t *si_data, uint32 si_data_len,
                            uint8 **buf_ptr, uint64 *buf_len)
{
    uint32 i;
    const iovec_app_t *si_data_orig = si_data;
    uint8 *buf = NULL;
    wasi_errno_t error;

    error = allocate_iovec_app_buffer(module_inst, si_data, si_data_len,
                                      buf_ptr, buf_len);
    if (error != __WASI_ESUCCESS) {
        return error;
    }

    buf = *buf_ptr;
    si_data = si_data_orig;
    for (i = 0; i < si_data_len; i++, si_data++) {
        char *native_addr;

        if (!validate_app_addr(si_data->buf_offset, si_data->buf_len)) {
            wasm_runtime_free(*buf_ptr);
            return __WASI_EINVAL;
        }

        native_addr = (char *)addr_app_to_native(si_data->buf_offset);
        bh_memcpy_s(buf, si_data->buf_len, native_addr, si_data->buf_len);
        buf += si_data->buf_len;
    }

    return __WASI_ESUCCESS;
}

static wasi_errno_t
wasi_sock_send(wasm_exec_env_t exec_env, wasi_fd_t sock,
               const iovec_app_t *si_data, uint32 si_data_len,
               wasi_siflags_t si_flags, uint32 *so_data_len)
{
    /**
     * si_data_len is the length of a list of iovec_app_t, which head is
     * si_data. so_data_len is the number of bytes sent
     **/
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    uint64 buf_size = 0;
    uint8 *buf = NULL;
    wasi_errno_t err;
    size_t send_bytes = 0;

    if (!wasi_ctx) {
        return __WASI_EINVAL;
    }

    if (!validate_native_addr(so_data_len, sizeof(uint32)))
        return __WASI_EINVAL;

    err = convert_iovec_app_to_buffer(module_inst, si_data, si_data_len, &buf,
                                      &buf_size);
    if (err != __WASI_ESUCCESS)
        return err;

    *so_data_len = 0;
    err = wasmtime_ssp_sock_send(curfds, sock, buf, buf_size, &send_bytes);
    *so_data_len = (uint32)send_bytes;

    wasm_runtime_free(buf);

    return err;
}

static wasi_errno_t
wasi_sock_send_to(wasm_exec_env_t exec_env, wasi_fd_t sock,
                  const iovec_app_t *si_data, uint32 si_data_len,
                  wasi_siflags_t si_flags, const __wasi_addr_t *dest_addr,
                  uint32 *so_data_len)
{
    /**
     * si_data_len is the length of a list of iovec_app_t, which head is
     * si_data. so_data_len is the number of bytes sent
     **/
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);
    uint64 buf_size = 0;
    uint8 *buf = NULL;
    wasi_errno_t err;
    size_t send_bytes = 0;
    struct addr_pool *addr_pool = wasi_ctx_get_addr_pool(module_inst, wasi_ctx);

    if (!wasi_ctx) {
        return __WASI_EINVAL;
    }

    if (!validate_native_addr(so_data_len, sizeof(uint32)))
        return __WASI_EINVAL;

    err = convert_iovec_app_to_buffer(module_inst, si_data, si_data_len, &buf,
                                      &buf_size);
    if (err != __WASI_ESUCCESS)
        return err;

    *so_data_len = 0;
    err = wasmtime_ssp_sock_send_to(curfds, addr_pool, sock, buf, buf_size,
                                    si_flags, dest_addr, &send_bytes);
    *so_data_len = (uint32)send_bytes;

    wasm_runtime_free(buf);

    return err;
}

static wasi_errno_t
wasi_sock_shutdown(wasm_exec_env_t exec_env, wasi_fd_t sock, wasi_sdflags_t how)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasi_ctx_t wasi_ctx = get_wasi_ctx(module_inst);
    struct fd_table *curfds = wasi_ctx_get_curfds(module_inst, wasi_ctx);

    if (!wasi_ctx)
        return __WASI_EINVAL;

    return wasmtime_ssp_sock_shutdown(curfds, sock);
}

static wasi_errno_t
wasi_sched_yield(wasm_exec_env_t exec_env)
{
    return wasmtime_ssp_sched_yield();
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
    REG_NATIVE_FUNC(sock_accept, "(ii*)i"),
    REG_NATIVE_FUNC(sock_addr_local, "(i*)i"),
    REG_NATIVE_FUNC(sock_addr_remote, "(i*)i"),
    REG_NATIVE_FUNC(sock_addr_resolve, "($$**i*)i"),
    REG_NATIVE_FUNC(sock_bind, "(i*)i"),
    REG_NATIVE_FUNC(sock_close, "(i)i"),
    REG_NATIVE_FUNC(sock_connect, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_broadcast, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_keep_alive, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_linger, "(i**)i"),
    REG_NATIVE_FUNC(sock_get_recv_buf_size, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_recv_timeout, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_reuse_addr, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_reuse_port, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_send_buf_size, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_send_timeout, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_tcp_fastopen_connect, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_tcp_keep_idle, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_tcp_keep_intvl, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_tcp_no_delay, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_tcp_quick_ack, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_ip_multicast_loop, "(ii*)i"),
    REG_NATIVE_FUNC(sock_get_ip_multicast_ttl, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_ip_ttl, "(i*)i"),
    REG_NATIVE_FUNC(sock_get_ipv6_only, "(i*)i"),
    REG_NATIVE_FUNC(sock_listen, "(ii)i"),
    REG_NATIVE_FUNC(sock_open, "(iii*)i"),
    REG_NATIVE_FUNC(sock_recv, "(i*ii**)i"),
    REG_NATIVE_FUNC(sock_recv_from, "(i*ii**)i"),
    REG_NATIVE_FUNC(sock_send, "(i*ii*)i"),
    REG_NATIVE_FUNC(sock_send_to, "(i*ii**)i"),
    REG_NATIVE_FUNC(sock_set_broadcast, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_keep_alive, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_linger, "(iii)i"),
    REG_NATIVE_FUNC(sock_set_recv_buf_size, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_recv_timeout, "(iI)i"),
    REG_NATIVE_FUNC(sock_set_reuse_addr, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_reuse_port, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_send_buf_size, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_send_timeout, "(iI)i"),
    REG_NATIVE_FUNC(sock_set_tcp_fastopen_connect, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_tcp_keep_idle, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_tcp_keep_intvl, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_tcp_no_delay, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_tcp_quick_ack, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_ip_multicast_loop, "(iii)i"),
    REG_NATIVE_FUNC(sock_set_ip_multicast_ttl, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_ip_add_membership, "(i*i)i"),
    REG_NATIVE_FUNC(sock_set_ip_drop_membership, "(i*i)i"),
    REG_NATIVE_FUNC(sock_set_ip_ttl, "(ii)i"),
    REG_NATIVE_FUNC(sock_set_ipv6_only, "(ii)i"),
    REG_NATIVE_FUNC(sock_shutdown, "(ii)i"),
    REG_NATIVE_FUNC(sched_yield, "()i"),
};

uint32
get_libc_wasi_export_apis(NativeSymbol **p_libc_wasi_apis)
{
    *p_libc_wasi_apis = native_symbols_libc_wasi;
    return sizeof(native_symbols_libc_wasi) / sizeof(NativeSymbol);
}
