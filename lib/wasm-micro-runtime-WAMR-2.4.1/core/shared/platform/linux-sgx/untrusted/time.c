/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <stdbool.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>

/** time clock **/
int
ocall_clock_gettime(unsigned clock_id, void *tp_buf, unsigned int tp_buf_size)
{
    return clock_gettime((clockid_t)clock_id, (struct timespec *)tp_buf);
}

int
ocall_clock_getres(int clock_id, void *res_buf, unsigned int res_buf_size)
{
    return clock_getres(clock_id, (struct timespec *)res_buf);
}

int
ocall_utimensat(int dirfd, const char *pathname, const void *times_buf,
                unsigned int times_buf_size, int flags)
{
    return utimensat(dirfd, pathname, (struct timespec *)times_buf, flags);
}

int
ocall_futimens(int fd, const void *times_buf, unsigned int times_buf_size)
{
    return futimens(fd, (struct timespec *)times_buf);
}

int
ocall_clock_nanosleep(unsigned clock_id, int flags, const void *req_buf,
                      unsigned int req_buf_size, const void *rem_buf,
                      unsigned int rem_buf_size)
{
    return clock_nanosleep((clockid_t)clock_id, flags,
                           (struct timespec *)req_buf,
                           (struct timespec *)rem_buf);
}
