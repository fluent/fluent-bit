/*
 * Copyright (C) 2020 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_common.h"
#include "bh_log.h"
#include "wasm_export.h"
#include "../interpreter/wasm.h"

#if defined(__linux__)
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
#define HAVE_SYSCALL_GETRANDOM
#include <sys/syscall.h>
#endif
#endif

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

static void
invoke_viiii_wrapper(wasm_exec_env_t exec_env, uint32 elem_idx, int arg0,
                     int arg1, int arg2, int arg3)
{
    uint32 argv[4];
    bool ret;

    argv[0] = arg0;
    argv[1] = arg1;
    argv[2] = arg2;
    argv[3] = arg3;
    ret = wasm_runtime_call_indirect(exec_env, elem_idx, 4, argv);
    (void)ret;
}

static void
invoke_viii_wrapper(wasm_exec_env_t exec_env, uint32 elem_idx, int arg0,
                    int arg1, int arg2)
{
    uint32 argv[4];
    bool ret;

    argv[0] = arg0;
    argv[1] = arg1;
    argv[2] = arg2;
    ret = wasm_runtime_call_indirect(exec_env, elem_idx, 3, argv);
    (void)ret;
}

static void
invoke_vii_wrapper(wasm_exec_env_t exec_env, uint32 elem_idx, int arg0,
                   int arg1)
{
    uint32 argv[4];
    bool ret;

    argv[0] = arg0;
    argv[1] = arg1;
    ret = wasm_runtime_call_indirect(exec_env, elem_idx, 2, argv);
    (void)ret;
}

static void
invoke_vi_wrapper(wasm_exec_env_t exec_env, uint32 elem_idx, int arg0)
{
    uint32 argv[4];
    bool ret;

    argv[0] = arg0;
    ret = wasm_runtime_call_indirect(exec_env, elem_idx, 1, argv);
    (void)ret;
}

static int
invoke_iii_wrapper(wasm_exec_env_t exec_env, uint32 elem_idx, int arg0,
                   int arg1)
{
    uint32 argv[4];
    bool ret;

    argv[0] = arg0;
    argv[1] = arg1;
    ret = wasm_runtime_call_indirect(exec_env, elem_idx, 2, argv);
    return ret ? argv[0] : 0;
}

static int
invoke_ii_wrapper(wasm_exec_env_t exec_env, uint32 elem_idx, int arg0)
{
    uint32 argv[4];
    bool ret;

    argv[0] = arg0;
    ret = wasm_runtime_call_indirect(exec_env, elem_idx, 1, argv);
    return ret ? argv[0] : 0;
}

struct timespec_emcc {
    int tv_sec;
    int tv_nsec;
};

struct stat_emcc {
    unsigned st_dev;
    int __st_dev_padding;
    unsigned __st_ino_truncated;
    unsigned st_mode;
    unsigned st_nlink;
    unsigned st_uid;
    unsigned st_gid;
    unsigned st_rdev;
    int __st_rdev_padding;
    int64 st_size;
    int st_blksize;
    int st_blocks;
    struct timespec_emcc st_atim;
    struct timespec_emcc st_mtim;
    struct timespec_emcc st_ctim;
    int64 st_ino;
};

static int
open_wrapper(wasm_exec_env_t exec_env, const char *pathname, int flags,
             int mode)
{
    if (pathname == NULL)
        return -1;
    return open(pathname, flags, mode);
}

static int
__sys_read_wrapper(wasm_exec_env_t exec_env, int fd, void *buf, uint32 count)
{
    return read(fd, buf, count);
}

static void
statbuf_native2app(const struct stat *statbuf_native,
                   struct stat_emcc *statbuf_app)
{
    statbuf_app->st_dev = (unsigned)statbuf_native->st_dev;
    statbuf_app->__st_ino_truncated = (unsigned)statbuf_native->st_ino;
    statbuf_app->st_mode = (unsigned)statbuf_native->st_mode;
    statbuf_app->st_nlink = (unsigned)statbuf_native->st_nlink;
    statbuf_app->st_uid = (unsigned)statbuf_native->st_uid;
    statbuf_app->st_gid = (unsigned)statbuf_native->st_gid;
    statbuf_app->st_rdev = (unsigned)statbuf_native->st_rdev;
    statbuf_app->st_size = (int64)statbuf_native->st_size;
    statbuf_app->st_blksize = (unsigned)statbuf_native->st_blksize;
    statbuf_app->st_blocks = (unsigned)statbuf_native->st_blocks;
    statbuf_app->st_ino = (int64)statbuf_native->st_ino;
#if defined(__APPLE__)
    statbuf_app->st_atim.tv_sec = (int)statbuf_native->st_atimespec.tv_sec;
    statbuf_app->st_atim.tv_nsec = (int)statbuf_native->st_atimespec.tv_nsec;
    statbuf_app->st_mtim.tv_sec = (int)statbuf_native->st_mtimespec.tv_sec;
    statbuf_app->st_mtim.tv_nsec = (int)statbuf_native->st_mtimespec.tv_nsec;
    statbuf_app->st_ctim.tv_sec = (int)statbuf_native->st_ctimespec.tv_sec;
    statbuf_app->st_ctim.tv_nsec = (int)statbuf_native->st_ctimespec.tv_nsec;
#else
    statbuf_app->st_atim.tv_sec = (int)statbuf_native->st_atim.tv_sec;
    statbuf_app->st_atim.tv_nsec = (int)statbuf_native->st_atim.tv_nsec;
    statbuf_app->st_mtim.tv_sec = (int)statbuf_native->st_mtim.tv_sec;
    statbuf_app->st_mtim.tv_nsec = (int)statbuf_native->st_mtim.tv_nsec;
    statbuf_app->st_ctim.tv_sec = (int)statbuf_native->st_ctim.tv_sec;
    statbuf_app->st_ctim.tv_nsec = (int)statbuf_native->st_ctim.tv_nsec;
#endif
}

static int
__sys_stat64_wrapper(wasm_exec_env_t exec_env, const char *pathname,
                     struct stat_emcc *statbuf_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    int ret;
    struct stat statbuf;

    if (!validate_native_addr((void *)statbuf_app,
                              (uint64)sizeof(struct stat_emcc)))
        return -1;

    if (pathname == NULL)
        return -1;

    ret = stat(pathname, &statbuf);
    if (ret == 0)
        statbuf_native2app(&statbuf, statbuf_app);
    return ret;
}

static int
__sys_fstat64_wrapper(wasm_exec_env_t exec_env, int fd,
                      struct stat_emcc *statbuf_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    int ret;
    struct stat statbuf;

    if (!validate_native_addr((void *)statbuf_app,
                              (uint64)sizeof(struct stat_emcc)))
        return -1;

    if (fd <= 0)
        return -1;

    ret = fstat(fd, &statbuf);
    if (ret == 0)
        statbuf_native2app(&statbuf, statbuf_app);
    return ret;
}

static int
mmap_wrapper(wasm_exec_env_t exec_env, void *addr, int length, int prot,
             int flags, int fd, int64 offset)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    uint32 buf_offset;
    char *buf;
    int size_read;

    buf_offset = module_malloc((uint64)length, (void **)&buf);
    if (buf_offset == 0)
        return -1;

    if (fd <= 0)
        return -1;

    if (lseek(fd, offset, SEEK_SET) == -1)
        return -1;

    size_read = read(fd, buf, length);
    (void)size_read;
    return buf_offset;
}

static int
munmap_wrapper(wasm_exec_env_t exec_env, uint32 buf_offset, int length)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    module_free((uint64)buf_offset);
    return 0;
}

static int
__munmap_wrapper(wasm_exec_env_t exec_env, uint32 buf_offset, int length)
{
    return munmap_wrapper(exec_env, buf_offset, length);
}

static int
getentropy_wrapper(wasm_exec_env_t exec_env, void *buffer, uint32 length)
{
    if (buffer == NULL)
        return -1;
#if defined(HAVE_SYSCALL_GETRANDOM)
    return syscall(SYS_getrandom, buffer, length, 0);
#else
    return getentropy(buffer, length);
#endif
}

static int
setjmp_wrapper(wasm_exec_env_t exec_env, void *jmp_buf)
{
    LOG_DEBUG("setjmp() called\n");
    return 0;
}

static void
longjmp_wrapper(wasm_exec_env_t exec_env, void *jmp_buf, int val)
{
    LOG_DEBUG("longjmp() called\n");
}

#if !defined(BH_PLATFORM_LINUX_SGX)
static FILE *file_list[32] = { 0 };

static int
get_free_file_slot()
{
    unsigned int i;

    for (i = 0; i < sizeof(file_list) / sizeof(FILE *); i++) {
        if (file_list[i] == NULL)
            return (int)i;
    }
    return -1;
}

static int
fopen_wrapper(wasm_exec_env_t exec_env, const char *pathname, const char *mode)
{
    FILE *file;
    int file_id;

    if (pathname == NULL || mode == NULL)
        return 0;

    if ((file_id = get_free_file_slot()) == -1)
        return 0;

    file = fopen(pathname, mode);
    if (!file)
        return 0;

    file_list[file_id] = file;
    return file_id + 1;
}

static uint32
fread_wrapper(wasm_exec_env_t exec_env, void *ptr, uint32 size, uint32 nmemb,
              int file_id)
{
    FILE *file;

    file_id = file_id - 1;
    if ((unsigned)file_id >= sizeof(file_list) / sizeof(FILE *)) {
        return 0;
    }
    if ((file = file_list[file_id]) == NULL) {
        return 0;
    }
    return (uint32)fread(ptr, size, nmemb, file);
}

static int
fseeko_wrapper(wasm_exec_env_t exec_env, int file_id, int64 offset, int whence)
{
    FILE *file;

    file_id = file_id - 1;
    if ((unsigned)file_id >= sizeof(file_list) / sizeof(FILE *)) {
        return -1;
    }
    if ((file = file_list[file_id]) == NULL) {
        return -1;
    }
    return (uint32)fseek(file, offset, whence);
}

static uint32
emcc_fwrite_wrapper(wasm_exec_env_t exec_env, const void *ptr, uint32 size,
                    uint32 nmemb, int file_id)
{
    FILE *file;

    file_id = file_id - 1;
    if ((unsigned)file_id >= sizeof(file_list) / sizeof(FILE *)) {
        return 0;
    }
    if ((file = file_list[file_id]) == NULL) {
        return 0;
    }
    return (uint32)fwrite(ptr, size, nmemb, file);
}

static int
feof_wrapper(wasm_exec_env_t exec_env, int file_id)
{
    FILE *file;

    file_id = file_id - 1;
    if ((unsigned)file_id >= sizeof(file_list) / sizeof(FILE *))
        return 1;
    if ((file = file_list[file_id]) == NULL)
        return 1;
    return feof(file);
}

static int
fclose_wrapper(wasm_exec_env_t exec_env, int file_id)
{
    FILE *file;

    file_id = file_id - 1;
    if ((unsigned)file_id >= sizeof(file_list) / sizeof(FILE *))
        return -1;
    if ((file = file_list[file_id]) == NULL)
        return -1;
    file_list[file_id] = NULL;
    return fclose(file);
}

static int
__sys_mkdir_wrapper(wasm_exec_env_t exec_env, const char *pathname, int mode)
{
    if (!pathname)
        return -1;
    return mkdir(pathname, mode);
}

static int
__sys_rmdir_wrapper(wasm_exec_env_t exec_env, const char *pathname)
{
    if (!pathname)
        return -1;
    return rmdir(pathname);
}

static int
__sys_unlink_wrapper(wasm_exec_env_t exec_env, const char *pathname)
{
    if (!pathname)
        return -1;
    return unlink(pathname);
}

static uint32
__sys_getcwd_wrapper(wasm_exec_env_t exec_env, char *buf, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char *ret;

    if (!buf)
        return -1;

    ret = getcwd(buf, size);
    return ret ? (uint32)addr_native_to_app(ret) : 0;
}

#include <sys/utsname.h>

struct utsname_app {
    char sysname[64];
    char nodename[64];
    char release[64];
    char version[64];
    char machine[64];
    char domainname[64];
};

static int
__sys_uname_wrapper(wasm_exec_env_t exec_env, struct utsname_app *uname_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    struct utsname uname_native = { 0 };
    uint32 length;

    if (!validate_native_addr(uname_app, (uint64)sizeof(struct utsname_app)))
        return -1;

    if (uname(&uname_native) != 0) {
        return -1;
    }

    memset(uname_app, 0, sizeof(struct utsname_app));

    length = strlen(uname_native.sysname);
    if (length > sizeof(uname_app->sysname) - 1)
        length = sizeof(uname_app->sysname) - 1;
    bh_memcpy_s(uname_app->sysname, sizeof(uname_app->sysname),
                uname_native.sysname, length);

    length = strlen(uname_native.nodename);
    if (length > sizeof(uname_app->nodename) - 1)
        length = sizeof(uname_app->nodename) - 1;
    bh_memcpy_s(uname_app->nodename, sizeof(uname_app->nodename),
                uname_native.nodename, length);

    length = strlen(uname_native.release);
    if (length > sizeof(uname_app->release) - 1)
        length = sizeof(uname_app->release) - 1;
    bh_memcpy_s(uname_app->release, sizeof(uname_app->release),
                uname_native.release, length);

    length = strlen(uname_native.version);
    if (length > sizeof(uname_app->version) - 1)
        length = sizeof(uname_app->version) - 1;
    bh_memcpy_s(uname_app->version, sizeof(uname_app->version),
                uname_native.version, length);

#ifdef _GNU_SOURCE
    length = strlen(uname_native.domainname);
    if (length > sizeof(uname_app->domainname) - 1)
        length = sizeof(uname_app->domainname) - 1;
    bh_memcpy_s(uname_app->domainname, sizeof(uname_app->domainname),
                uname_native.domainname, length);
#endif

    return 0;
}

static void
emscripten_notify_memory_growth_wrapper(wasm_exec_env_t exec_env, int i)
{
    (void)i;
}

static void
emscripten_sleep_wrapper(wasm_exec_env_t exec_env, int timeout_ms)
{
    unsigned int sec;
    useconds_t us;

    if (timeout_ms <= 0)
        return;

    sec = timeout_ms / 1000;
    us = (timeout_ms % 1000) * 1000;

    if (sec > 0)
        sleep(sec);
    if (us > 0)
        usleep(us);
}

static void
emscripten_thread_sleep_wrapper(wasm_exec_env_t exec_env, double timeout_ms)
{
    uint64 ms = (uint64)timeout_ms;
    uint64 sec = ms / 1000, us = (ms % 1000) * 1000;

    if (sec > 0)
        sleep(sec);
    if (us > 0)
        usleep(us);
}

#endif /* end of BH_PLATFORM_LINUX_SGX */

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }
/* clang-format off */

static NativeSymbol native_symbols_libc_emcc[] = {
    REG_NATIVE_FUNC(invoke_viiii, "(iiiii)"),
    REG_NATIVE_FUNC(invoke_viii, "(iiii)"),
    REG_NATIVE_FUNC(invoke_vii, "(iii)"),
    REG_NATIVE_FUNC(invoke_vi, "(ii)"),
    REG_NATIVE_FUNC(invoke_iii, "(iii)i"),
    REG_NATIVE_FUNC(invoke_ii, "(ii)i"),
    REG_NATIVE_FUNC(open, "($ii)i"),
    REG_NATIVE_FUNC(__sys_read, "(i*~)i"),
    REG_NATIVE_FUNC(__sys_stat64, "($*)i"),
    REG_NATIVE_FUNC(__sys_fstat64, "(i*)i"),
    REG_NATIVE_FUNC(mmap, "(*iiiiI)i"),
    REG_NATIVE_FUNC(munmap, "(ii)i"),
    REG_NATIVE_FUNC(__munmap, "(ii)i"),
    REG_NATIVE_FUNC(getentropy, "(*~)i"),
    REG_NATIVE_FUNC(setjmp, "(*)i"),
    REG_NATIVE_FUNC(longjmp, "(*i)"),
#if !defined(BH_PLATFORM_LINUX_SGX)
    REG_NATIVE_FUNC(fopen, "($$)i"),
    REG_NATIVE_FUNC(fread, "(*iii)i"),
    REG_NATIVE_FUNC(fseeko, "(iIi)i"),
    REG_NATIVE_FUNC(emcc_fwrite, "(*iii)i"),
    REG_NATIVE_FUNC(feof, "(i)i"),
    REG_NATIVE_FUNC(fclose, "(i)i"),
    REG_NATIVE_FUNC(__sys_mkdir, "($i)i"),
    REG_NATIVE_FUNC(__sys_rmdir, "($)i"),
    REG_NATIVE_FUNC(__sys_unlink, "($)i"),
    REG_NATIVE_FUNC(__sys_getcwd, "(*~)i"),
    REG_NATIVE_FUNC(__sys_uname, "(*)i"),
    REG_NATIVE_FUNC(emscripten_notify_memory_growth, "(i)"),
    REG_NATIVE_FUNC(emscripten_sleep, "(i)"),
    REG_NATIVE_FUNC(emscripten_thread_sleep, "(F)"),
#endif /* end of BH_PLATFORM_LINUX_SGX */
};

uint32
get_libc_emcc_export_apis(NativeSymbol **p_libc_emcc_apis)
{
    *p_libc_emcc_apis = native_symbols_libc_emcc;
    return sizeof(native_symbols_libc_emcc) / sizeof(NativeSymbol);
}
