/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef WASI_NN_LOGGER_H
#define WASI_NN_LOGGER_H

#include <stdio.h>
#include <string.h>

#define __FILENAME__ \
    (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/* Disable a level by removing the define */
#ifndef NN_LOG_LEVEL
/*
    0 -> debug, info, warn, err
    1 -> info, warn, err
    2 -> warn, err
    3 -> err
    4 -> NO LOGS
*/
#define NN_LOG_LEVEL 0
#endif

// Definition of the levels
#if NN_LOG_LEVEL <= 3
#define NN_ERR_PRINTF(fmt, ...)                                              \
    do {                                                                     \
        printf("[%s:%d ERROR] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__); \
        printf("\n");                                                        \
        fflush(stdout);                                                      \
    } while (0)
#else
#define NN_ERR_PRINTF(fmt, ...)
#endif
#if NN_LOG_LEVEL <= 2
#define NN_WARN_PRINTF(fmt, ...)                                               \
    do {                                                                       \
        printf("[%s:%d WARNING] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__); \
        printf("\n");                                                          \
        fflush(stdout);                                                        \
    } while (0)
#else
#define NN_WARN_PRINTF(fmt, ...)
#endif
#if NN_LOG_LEVEL <= 1
#define NN_INFO_PRINTF(fmt, ...)                                            \
    do {                                                                    \
        printf("[%s:%d INFO] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__); \
        printf("\n");                                                       \
        fflush(stdout);                                                     \
    } while (0)
#else
#define NN_INFO_PRINTF(fmt, ...)
#endif
#if NN_LOG_LEVEL <= 0
#define NN_DBG_PRINTF(fmt, ...)                                              \
    do {                                                                     \
        printf("[%s:%d DEBUG] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__); \
        printf("\n");                                                        \
        fflush(stdout);                                                      \
    } while (0)
#else
#define NN_DBG_PRINTF(fmt, ...)
#endif

#endif
