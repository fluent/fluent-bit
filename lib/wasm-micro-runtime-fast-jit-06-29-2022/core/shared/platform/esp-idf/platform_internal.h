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

#define BH_APPLET_PRESERVED_STACK_SIZE (2 * BH_KB)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 5

#ifdef __cplusplus
}
#endif

#endif
