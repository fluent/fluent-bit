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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>

void cio_log_print(void *ctx, int level, const char *file, int line,
                   const char *fmt, ...)
{
    int ret;
    char buf[CIO_LOG_BUF_SIZE];
    va_list args;
    struct cio_ctx *cio = ctx;

    if (!cio->options.log_cb) {
       return;
    }

    if (level > cio->options.log_level) {
        return;
    }

    va_start(args, fmt);
    ret = vsnprintf(buf, CIO_LOG_BUF_SIZE - 1, fmt, args);

    if (ret >= 0) {
        buf[ret] = '\0';
    }
    va_end(args);

    cio->options.log_cb(ctx, level, file, line, buf);
}

int cio_errno_print(int errnum, const char *file, int line)
{
    char buf[256];

    strerror_r(errnum, buf, sizeof(buf) - 1);
    fprintf(stderr, "[%s:%i errno=%i] %s\n",
            file, line, errnum, buf);
    return 0;
}

#ifdef _WIN32
void cio_winapi_error_print(const char *func, int line)
{
    int error = GetLastError();
    char buf[256];
    int success;

    success = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
                             FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL,
                             error,
                             LANG_SYSTEM_DEFAULT,
                             buf,
                             sizeof(buf),
                             NULL);
    if (success) {
        fprintf(stderr, "[%s() line=%i error=%i] %s\n", func, line, error, buf);
    }
    else {
        fprintf(stderr, "[%s() line=%i error=%i] Win32 API failed\n", func, line, error);
    }
}
#endif
