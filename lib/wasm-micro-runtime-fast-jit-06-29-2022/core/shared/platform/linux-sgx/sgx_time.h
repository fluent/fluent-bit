/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SGX_TIME_H
#define _SGX_TIME_H

#ifdef __cplusplus
extern "C" {
#endif

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3

#define UTIME_NOW 0x3fffffff
#define UTIME_OMIT 0x3ffffffe
#define TIMER_ABSTIME 1

typedef long int time_t;

typedef int clockid_t;

struct timespec {
    time_t tv_sec;
    long tv_nsec;
};

int
clock_getres(int clock_id, struct timespec *res);

int
clock_gettime(clockid_t clock_id, struct timespec *tp);

int
utimensat(int dirfd, const char *pathname, const struct timespec times[2],
          int flags);
int
futimens(int fd, const struct timespec times[2]);
int
clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *request,
                struct timespec *remain);

#ifdef __cplusplus
}
#endif

#endif /* end of _SGX_TIME_H */
