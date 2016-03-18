/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>

#include <mk_core.h>
#include <fluent-bit/flb_log.h>

#ifdef HAVE_C_TLS
__thread struct flb_log *flb_log_ctx;
#endif

struct flb_log *flb_log_init(int type, int level, char *out)
{
    struct flb_log *log;

    log = malloc(sizeof(struct flb_log));
    if (!log) {
        perror("malloc");
        return NULL;
    }

    /* Only supporting STDERR for now */
    log->type  = FLB_LOG_STDERR;
    log->level = level;
    log->out   = NULL;

    FLB_TLS_INIT();
    FLB_TLS_SET(flb_log_ctx, log);

    return log;
}

void flb_log_print(int type, char *file, int line, const char *fmt, ...)
{
    time_t now;
    const char *header_color = NULL;
    const char *header_title = NULL;
    const char *bold_color = ANSI_BOLD;
    const char *reset_color = ANSI_RESET;
    struct tm result;
    struct tm *current;
    va_list args;

    va_start(args, fmt);

    switch (type) {
    case FLB_LOG_INFO:
        header_title = "info";
        header_color = ANSI_GREEN;
        break;
    case FLB_LOG_WARN:
        header_title = "warn";
        header_color = ANSI_YELLOW;
        break;
    case FLB_LOG_ERROR:
        header_title = "error";
        header_color = ANSI_RED;
        break;
    case FLB_LOG_DEBUG:
        header_title = "debug";
        header_color = ANSI_YELLOW;
        break;
    case FLB_LOG_TRACE:
        header_title = "trace";
        header_color = ANSI_BLUE;
        break;
    }

    /* Only print colors to a terminal */
    if (!isatty(STDOUT_FILENO)) {
        header_color = "";
        bold_color = "";
        reset_color = "";
    }

    now = time(NULL);
    current = localtime_r(&now, &result);

    fprintf(stderr, "%s[%s%i/%02i/%02i %02i:%02i:%02i%s]%s ",
            bold_color, reset_color,
            current->tm_year + 1900,
            current->tm_mon + 1,
            current->tm_mday,
            current->tm_hour,
            current->tm_min,
            current->tm_sec,
            bold_color, reset_color);

    fprintf(stderr, "%s[%s%5s%s]%s ",
            "", header_color, header_title, reset_color, "");

    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "%s\n", reset_color);
}

int flb_log_stop(struct flb_log *log)
{
    free(log);
    return 0;
}

#ifndef HAVE_C_TLS
int flb_log_check(int level) {
    struct flb_log *lc = FLB_TLS_GET(flb_log_ctx);

    if (lc->level < level)
        return FLB_FALSE;
    else
        return FLB_TRUE;
}
#endif
