/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <dirent.h>

#include "esp_pthread.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BH_PLATFORM_ESP_IDF
#define BH_PLATFORM_ESP_IDF
#endif

typedef pthread_t korp_tid;
typedef pthread_mutex_t korp_mutex;
typedef pthread_cond_t korp_cond;
typedef pthread_t korp_thread;
typedef pthread_rwlock_t korp_rwlock;
typedef unsigned int korp_sem;

#define OS_THREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

#define BH_APPLET_PRESERVED_STACK_SIZE (2 * BH_KB)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 5

/* Special value for tv_nsec field of timespec */

#define UTIME_NOW ((1l << 30) - 1l)
#ifndef __cplusplus
#define UTIME_OMIT ((1l << 30) - 2l)
#endif

/* Below parts of d_type define are ported from Nuttx, under Apache License v2.0
 */

/* Following macros are defined in espressif GCC of esp-idf v5.3
 */

#define DTYPE_UNKNOWN 0
#define DTYPE_FILE 1
#define DTYPE_DIRECTORY 2
#define DTYPE_CHR 4
#define DTYPE_BLK 5
#define DTYPE_FIFO 8
#define DTYPE_LINK 10
#define DTYPE_SOCK 12

/* Following macros are not defined in espressif GCC of esp-idf v5.3
 */

#define DTYPE_SEM 100
#define DTYPE_MQ 101
#define DTYPE_SHM 102
#define DTYPE_MTD 103

/* The d_type field of the dirent structure is not specified by POSIX.  It
 * is a non-standard, 4.5BSD extension that is implemented by most OSs.  A
 * POSIX compliant OS may not implement the d_type field at all.  Many OS's
 * (including glibc) may use the following alternative naming for the file
 * type names:
 */

#ifndef DT_UNKNOWN
#define DT_UNKNOWN DTYPE_UNKNOWN
#endif

#ifndef DT_FIFO
#define DT_FIFO DTYPE_FIFO
#endif

#ifndef DT_CHR
#define DT_CHR DTYPE_CHR
#endif

#ifndef DT_SEM
#define DT_SEM DTYPE_SEM
#endif

#ifndef DT_DIR
#define DT_DIR DTYPE_DIRECTORY
#endif

#ifndef DT_MQ
#define DT_MQ DTYPE_MQ
#endif

#ifndef DT_BLK
#define DT_BLK DTYPE_BLK
#endif

#ifndef DT_SHM
#define DT_SHM DTYPE_SHM
#endif

#ifndef DT_REG
#define DT_REG DTYPE_FILE
#endif

#ifndef DT_MTD
#define DT_MTD DTYPE_MTD
#endif

#ifndef DT_LNK
#define DT_LNK DTYPE_LINK
#endif

#ifndef DT_SOCK
#define DT_SOCK DTYPE_SOCK
#endif

static inline int
os_getpagesize()
{
    return 4096;
}

typedef int os_file_handle;
typedef DIR *os_dir_stream;
typedef int os_raw_file_handle;

static inline os_file_handle
os_get_invalid_handle(void)
{
    return -1;
}

#ifdef __cplusplus
}
#endif

#endif
