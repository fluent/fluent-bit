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
#define ENABLE_ERR_LOG
#define ENABLE_WARN_LOG
#define ENABLE_DBG_LOG
#define ENABLE_INFO_LOG

// Definition of the levels
#ifdef ENABLE_ERR_LOG
#define NN_ERR_PRINTF(fmt, ...)                                    \
    printf("[%s:%d] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__); \
    printf("\n");                                                  \
    fflush(stdout)
#else
#define NN_ERR_PRINTF(fmt, ...)
#endif
#ifdef ENABLE_WARN_LOG
#define NN_WARN_PRINTF(fmt, ...)                                   \
    printf("[%s:%d] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__); \
    printf("\n");                                                  \
    fflush(stdout)
#else
#define NN_WARN_PRINTF(fmt, ...)
#endif
#ifdef ENABLE_DBG_LOG
#define NN_DBG_PRINTF(fmt, ...)                                    \
    printf("[%s:%d] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__); \
    printf("\n");                                                  \
    fflush(stdout)
#else
#define NN_DBG_PRINTF(fmt, ...)
#endif
#ifdef ENABLE_INFO_LOG
#define NN_INFO_PRINTF(fmt, ...)                                   \
    printf("[%s:%d] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__); \
    printf("\n");                                                  \
    fflush(stdout)
#else
#define NN_INFO_PRINTF(fmt, ...)
#endif

#endif
