/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * Copyright (C) 2020 TU Bergakademie Freiberg Karl Fessel
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

/* Riot includes core */
#include <sched.h>
#include <thread.h>
#include <mutex.h>

/* Riot includes sys */
#include <sema.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifndef BH_PLATFORM_RIOT
#define BH_PLATFORM_RIOT
#endif

#define BH_APPLET_PRESERVED_STACK_SIZE (2 * BH_KB)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 7

typedef thread_t korp_thread;
typedef kernel_pid_t korp_tid;
typedef mutex_t korp_mutex;
typedef unsigned int korp_sem;

/* korp_rwlock is used in platform_api_extension.h,
   we just define the type to make the compiler happy */
typedef struct {
    int dummy;
} korp_rwlock;

/* typedef sema_t korp_sem; */

struct os_thread_wait_node;
typedef struct os_thread_wait_node *os_thread_wait_list;
typedef struct korp_cond {
    mutex_t wait_list_lock;
    os_thread_wait_list thread_wait_list;
} korp_cond;

#define os_printf printf
#define os_vprintf vprintf

/* The below types are used in platform_api_extension.h,
   we just define them to make the compiler happy */
typedef int os_file_handle;
typedef void *os_dir_stream;
typedef int os_raw_file_handle;

#if WA_MATH
/* clang-format off */
/* math functions which are not provided by os*/
double sqrt(double x);
double floor(double x);
double ceil(double x);
double fmin(double x, double y);
double fmax(double x, double y);
double rint(double x);
double fabs(double x);
double trunc(double x);
float sqrtf(float x);
float floorf(float x);
float ceilf(float x);
float fminf(float x, float y);
float fmaxf(float x, float y);
float rintf(float x);
float fabsf(float x);
float truncf(float x);
int signbit(double x);
int isnan(double x);
/* clang-format on */
#endif

static inline os_file_handle
os_get_invalid_handle(void)
{
    return -1;
}

/* There is no MMU in RIOT so the function return 1024 to make the compiler
   happy */
static inline int
os_getpagesize()
{
    return 1024;
}

#endif /* end of _BH_PLATFORM_H */
