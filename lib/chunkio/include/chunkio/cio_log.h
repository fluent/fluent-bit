/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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

#ifndef CIO_LOG_H
#define CIO_LOG_H

#include <errno.h>

#define CIO_LOG_BUF_SIZE  256

void cio_log_print(void *ctx, int level, const char *file, int line,
                     const char *fmt, ...);
int cio_errno_print(int errnum, const char *file, int line);

#define cio_log_error(ctx, fmt, ...)                    \
    cio_log_print(ctx, CIO_LOG_ERROR, __FILENAME__,     \
                  __LINE__, fmt, ##__VA_ARGS__)

#define cio_log_warn(ctx, fmt, ...)                 \
    cio_log_print(ctx, CIO_LOG_WARN, __FILENAME__,  \
                  __LINE__, fmt, ##__VA_ARGS__)

#define cio_log_info(ctx, fmt, ...)                 \
    cio_log_print(ctx, CIO_LOG_INFO, __FILENAME__,  \
                  __LINE__, fmt, ##__VA_ARGS__)

#define cio_log_debug(ctx, fmt, ...)                \
    cio_log_print(ctx, CIO_LOG_DEBUG, __FILENAME__, \
                  __LINE__, fmt, ##__VA_ARGS__)

#define cio_log_trace(ctx, fmt, ...)                \
    cio_log_print(ctx, CIO_LOG_TRACE, __FILENAME__, \
                  __LINE__, fmt, ##__VA_ARGS__)

#ifdef __FILENAME__
#define cio_errno() cio_errno_print(errno, __FILENAME__, __LINE__)
#else
#define cio_errno() cio_errno_print(errno, __FILE__, __LINE__)
#endif

#ifdef _WIN32
void cio_winapi_error_print(const char *func, int line);
#define cio_winapi_error() cio_winapi_error_print(__func__, __LINE__)
#endif

#endif
