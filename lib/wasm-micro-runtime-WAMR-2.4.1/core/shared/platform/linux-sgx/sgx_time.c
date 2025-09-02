/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"

#define TRACE_FUNC() os_printf("undefined %s\n", __FUNCTION__)
#define TRACE_OCALL_FAIL() os_printf("ocall %s failed!\n", __FUNCTION__)

int
ocall_clock_gettime(int *p_ret, unsigned clock_id, void *tp_buf,
                    unsigned int tp_buf_size);
int
ocall_clock_getres(int *p_ret, int clock_id, void *res_buf,
                   unsigned int res_buf_size);
int
ocall_utimensat(int *p_ret, int dirfd, const char *pathname,
                const void *times_buf, unsigned int times_buf_size, int flags);
int
ocall_futimens(int *p_ret, int fd, const void *times_buf,
               unsigned int times_buf_size);
int
ocall_clock_nanosleep(int *p_ret, unsigned clock_id, int flags,
                      const void *req_buf, unsigned int req_buf_size,
                      const void *rem_buf, unsigned int rem_buf_size);

uint64
os_time_get_boot_us()
{
#ifndef SGX_DISABLE_WASI
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return ((uint64)ts.tv_sec) * 1000 * 1000 + ((uint64)ts.tv_nsec) / 1000;
#else
    return 0;
#endif
}

uint64
os_time_thread_cputime_us(void)
{
#ifndef SGX_DISABLE_WASI
    struct timespec ts;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
        return 0;
    }

    return ((uint64)ts.tv_sec) * 1000 * 1000 + ((uint64)ts.tv_nsec) / 1000;
#else
    return 0;
#endif
}

#ifndef SGX_DISABLE_WASI

int
clock_getres(int clock_id, struct timespec *res)
{
    int ret;

    if (ocall_clock_getres(&ret, clock_id, (void *)res, sizeof(struct timespec))
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
clock_gettime(clockid_t clock_id, struct timespec *tp)
{
    int ret;

    if (ocall_clock_gettime(&ret, clock_id, (void *)tp, sizeof(struct timespec))
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
utimensat(int dirfd, const char *pathname, const struct timespec times[2],
          int flags)
{
    int ret;

    if (ocall_utimensat(&ret, dirfd, pathname, (void *)times,
                        sizeof(struct timespec) * 2, flags)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
futimens(int fd, const struct timespec times[2])
{
    int ret;

    if (ocall_futimens(&ret, fd, (void *)times, sizeof(struct timespec) * 2)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *request,
                struct timespec *remain)
{
    int ret;

    if (ocall_clock_nanosleep(&ret, clock_id, flags, (void *)request,
                              sizeof(struct timespec), (void *)remain,
                              sizeof(struct timespec))
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

#endif
