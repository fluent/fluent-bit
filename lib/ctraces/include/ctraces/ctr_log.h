/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef CTR_LOG_H
#define CTR_LOG_H

#include <errno.h>

/* Message types */
#define CTR_LOG_OFF     0
#define CTR_LOG_ERROR   1
#define CTR_LOG_WARN    2
#define CTR_LOG_INFO    3  /* default */
#define CTR_LOG_DEBUG   4
#define CTR_LOG_TRACE   5


#define CTR_LOG_BUF_SIZE  256

void ctr_log_print(void *ctx, int level, const char *file, int line,
                     const char *fmt, ...);
int ctr_errno_print(int errnum, const char *file, int line);

#define ctr_log_error(ctx, fmt, ...)                    \
    ctr_log_print(ctx, CTR_LOG_ERROR, __FILENAME__,     \
                  __LINE__, fmt, ##__VA_ARGS__)

#define ctr_log_warn(ctx, fmt, ...)                 \
    ctr_log_print(ctx, CTR_LOG_WARN, __FILENAME__,  \
                  __LINE__, fmt, ##__VA_ARGS__)

#define ctr_log_info(ctx, fmt, ...)                 \
    ctr_log_print(ctx, CTR_LOG_INFO, __FILENAME__,  \
                  __LINE__, fmt, ##__VA_ARGS__)

#define ctr_log_debug(ctx, fmt, ...)                \
    ctr_log_print(ctx, CTR_LOG_DEBUG, __FILENAME__, \
                  __LINE__, fmt, ##__VA_ARGS__)

#define ctr_log_trace(ctx, fmt, ...)                \
    ctr_log_print(ctx, CTR_LOG_TRACE, __FILENAME__, \
                  __LINE__, fmt, ##__VA_ARGS__)

#ifdef __FILENAME__
#define ctr_errno() ctr_errno_print(errno, __FILENAME__, __LINE__)
#else
#define ctr_errno() ctr_errno_print(errno, __FILE__, __LINE__)
#endif

#ifdef _WIN32
void ctr_winapi_error_print(const char *func, int line);
#define ctr_winapi_error() ctr_winapi_error_print(__func__, __LINE__)
#endif

#endif
