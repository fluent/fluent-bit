/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#ifndef CMT_LOG_H
#define CMT_LOG_H

#include <errno.h>

/* Message types */
#define CMT_LOG_OFF     0
#define CMT_LOG_ERROR   1
#define CMT_LOG_WARN    2
#define CMT_LOG_INFO    3  /* default */
#define CMT_LOG_DEBUG   4
#define CMT_LOG_TRACE   5


#define CMT_LOG_BUF_SIZE  256

void cmt_log_print(void *ctx, int level, const char *file, int line,
                     const char *fmt, ...);
int cmt_errno_print(int errnum, const char *file, int line);

#define cmt_log_error(ctx, fmt, ...)                        \
    cmt_log_print(ctx, CMT_LOG_ERROR, __CMT_FILENAME__,     \
                  __LINE__, fmt, ##__VA_ARGS__)

#define cmt_log_warn(ctx, fmt, ...)                         \
    cmt_log_print(ctx, CMT_LOG_WARN, __CMT_FILENAME__,      \
                  __LINE__, fmt, ##__VA_ARGS__)

#define cmt_log_info(ctx, fmt, ...)                         \
    cmt_log_print(ctx, CMT_LOG_INFO, __CMT_FILENAME__,      \
                  __LINE__, fmt, ##__VA_ARGS__)

#define cmt_log_debug(ctx, fmt, ...)                        \
    cmt_log_print(ctx, CMT_LOG_DEBUG, __CMT_FILENAME__,     \
                  __LINE__, fmt, ##__VA_ARGS__)

#define cmt_log_trace(ctx, fmt, ...)                        \
    cmt_log_print(ctx, CMT_LOG_TRACE, __CMT_FILENAME__,     \
                  __LINE__, fmt, ##__VA_ARGS__)

#ifdef __CMT_FILENAME__
#define cmt_errno() cmt_errno_print(errno, __CMT_FILENAME__, __LINE__)
#else
#define cmt_errno() cmt_errno_print(errno, __FILE__, __LINE__)
#endif

#ifdef _WIN32
void cmt_winapi_error_print(const char *func, int line);
#define cmt_winapi_error() cmt_winapi_error_print(__func__, __LINE__)
#endif

#endif
