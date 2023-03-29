/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <autoconf.h>
#include <zephyr.h>
#include <kernel.h>
#include <version.h>
#if KERNEL_VERSION_NUMBER >= 0x020200 /* version 2.2.0 */
#include <sys/printk.h>
#else
#include <misc/printk.h>
#endif
#include <inttypes.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#ifndef CONFIG_NET_BUF_USER_DATA_SIZE
#define CONFIG_NET_BUF_USER_DATA_SIZE 0
#endif
#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/net_ip.h>
#include <net/net_core.h>
#include <net/net_context.h>

#ifdef CONFIG_ARM_MPU
#include <arch/arm/aarch32/cortex_m/cmsis.h>
#endif

#ifndef BH_PLATFORM_ZEPHYR
#define BH_PLATFORM_ZEPHYR
#endif

#define BH_APPLET_PRESERVED_STACK_SIZE (2 * BH_KB)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 7

typedef struct k_thread korp_thread;
typedef korp_thread *korp_tid;
typedef struct k_mutex korp_mutex;
typedef unsigned int korp_sem;

struct os_thread_wait_node;
typedef struct os_thread_wait_node *os_thread_wait_list;
typedef struct korp_cond {
    struct k_mutex wait_list_lock;
    os_thread_wait_list thread_wait_list;
} korp_cond;

#ifndef Z_TIMEOUT_MS
#define Z_TIMEOUT_MS(ms) ms
#endif

/* clang-format off */
void abort(void);
size_t strspn(const char *s, const char *accept);
size_t strcspn(const char *s, const char *reject);

/* math functions which are not provided by os */
double atan(double x);
double atan2(double y, double x);
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
double pow(double x, double y);
double scalbn(double x, int n);

unsigned long long int strtoull(const char *nptr, char **endptr, int base);
double strtod(const char *nptr, char **endptr);
float strtof(const char *nptr, char **endptr);
/* clang-format on */

/**
 * @brief Allocate executable memroy
 *
 * @param size size of the memory to be allocated
 *
 * @return the address of the allocated memory if not NULL
 */
typedef void *(*exec_mem_alloc_func_t)(unsigned int size);

/**
 * @brief Release executable memroy
 *
 * @param the address of the executable memory to be released
 */
typedef void (*exec_mem_free_func_t)(void *addr);

/* Below function are called by external project to set related function
 * pointers that will be used to malloc/free executable memory. Otherwise
 * default mechanise will be used.
 */
void
set_exec_mem_alloc_func(exec_mem_alloc_func_t alloc_func,
                        exec_mem_free_func_t free_func);

#endif
