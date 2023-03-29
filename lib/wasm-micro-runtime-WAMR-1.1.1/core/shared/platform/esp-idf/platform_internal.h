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
typedef unsigned int korp_sem;

#define BH_APPLET_PRESERVED_STACK_SIZE (2 * BH_KB)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 5

/* Special value for tv_nsec field of timespec */

#define UTIME_NOW ((1l << 30) - 1l)
#ifndef __cplusplus
#define UTIME_OMIT ((1l << 30) - 2l)
#endif

#ifdef DT_UNKNOWN
#undef DT_UNKNOWN
#endif

#ifdef DT_REG
#undef DT_REG
#endif

#ifdef DT_DIR
#undef DT_DIR
#endif

/* Below parts of d_type define are ported from Nuttx, under Apache License v2.0
 */

/* File type code for the d_type field in dirent structure.
 * Note that because of the simplified filesystem organization of the NuttX,
 * top-level, pseudo-file system, an inode can be BOTH a file and a directory
 */

#define DTYPE_UNKNOWN 0
#define DTYPE_FIFO 1
#define DTYPE_CHR 2
#define DTYPE_SEM 3
#define DTYPE_DIRECTORY 4
#define DTYPE_MQ 5
#define DTYPE_BLK 6
#define DTYPE_SHM 7
#define DTYPE_FILE 8
#define DTYPE_MTD 9
#define DTYPE_LINK 10
#define DTYPE_SOCK 12

/* The d_type field of the dirent structure is not specified by POSIX.  It
 * is a non-standard, 4.5BSD extension that is implemented by most OSs.  A
 * POSIX compliant OS may not implement the d_type field at all.  Many OS's
 * (including glibc) may use the following alternative naming for the file
 * type names:
 */

#define DT_UNKNOWN DTYPE_UNKNOWN
#define DT_FIFO DTYPE_FIFO
#define DT_CHR DTYPE_CHR
#define DT_SEM DTYPE_SEM
#define DT_DIR DTYPE_DIRECTORY
#define DT_MQ DTYPE_MQ
#define DT_BLK DTYPE_BLK
#define DT_SHM DTYPE_SHM
#define DT_REG DTYPE_FILE
#define DT_MTD DTYPE_MTD
#define DT_LNK DTYPE_LINK
#define DT_SOCK DTYPE_SOCK

#ifdef __cplusplus
}
#endif

#endif
