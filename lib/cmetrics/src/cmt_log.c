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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_compat.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#ifdef _WIN32
    #define strerror_r(errnum, buf, buf_size) strerror_s(buf, buf_size, errnum)
#endif

void cmt_log_print(void *ctx, int level, const char *file, int line,
                   const char *fmt, ...)
{
    int ret;
    char buf[CMT_LOG_BUF_SIZE];
    va_list args;
    struct cmt *cmt = ctx;

    if (!cmt->log_cb) {
       return;
    }

    if (level > cmt->log_level) {
        return;
    }

    va_start(args, fmt);
    ret = vsnprintf(buf, CMT_LOG_BUF_SIZE - 1, fmt, args);

    if (ret >= 0) {
        buf[ret] = '\0';
    }
    va_end(args);

    cmt->log_cb(ctx, level, file, line, buf);
}

int cmt_errno_print(int errnum, const char *file, int line)
{
    char buf[256];

    strerror_r(errnum, buf, sizeof(buf) - 1);
    fprintf(stderr, "[%s:%i errno=%i] %s\n",
            file, line, errnum, buf);
    return 0;
}

#ifdef _WIN32
void cmt_winapi_error_print(const char *func, int line)
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
