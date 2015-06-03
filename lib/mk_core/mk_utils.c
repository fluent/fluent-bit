/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

#include "include/mk_macros.h"
#include "include/mk_utils.h"

#ifdef TRACE
#include <sys/time.h>

/*robust get environment variable that also checks __secure_getenv() */
static char *mk_utils_getenv(const char *arg)
{
#ifdef HAVE___SECURE_GETENV
    return __secure_getenv(arg);
#else
    return getenv(arg);
#endif
}

void mk_utils_trace(const char *component, int color, const char *function,
                    char *file, int line, const char* format, ...)
{
    va_list args;
    char *color_function  = NULL;
    char *color_fileline  = NULL;
    char *color_component = NULL;

    char *reset_color   = ANSI_RESET;
    char *magenta_color = ANSI_RESET ANSI_BOLD_MAGENTA;
    char *red_color     = ANSI_RESET ANSI_BOLD_RED;
    char *cyan_color    = ANSI_RESET ANSI_CYAN;

    struct timeval tv;
    struct timezone tz;

    if (env_trace_filter) {
        if (!strstr(env_trace_filter, file)) {
            return;
        }
    }

    /* Mutex lock */
    pthread_mutex_lock(&mutex_trace);

    gettimeofday(&tv, &tz);

    /* Switch message color */
    char* bgcolortype = mk_utils_getenv("MK_TRACE_BACKGROUND");

    if (!bgcolortype) {
        bgcolortype = "dark";
    }

    if (!strcmp(bgcolortype, "light")) {
        switch(color) {
        case MK_TRACE_CORE:
            color_component = ANSI_BOLD_GREEN;
            color_function  = ANSI_BOLD_MAGENTA;
            color_fileline  = ANSI_GREEN;
            break;
        case MK_TRACE_PLUGIN:
            color_component = ANSI_BOLD_GREEN;
            color_function  = ANSI_BLUE;
            color_fileline  = ANSI_GREEN;
            break;
        }
    }
    else { /* covering 'dark' and garbage values defaulting to 'dark' cases */
        switch(color) {
        case MK_TRACE_CORE:
            color_component = ANSI_BOLD_GREEN;
            color_function  = ANSI_YELLOW;
            color_fileline  = ANSI_BOLD_WHITE;
            break;
        case MK_TRACE_PLUGIN:
            color_component = ANSI_BOLD_BLUE;
            color_function  = ANSI_BLUE;
            color_fileline  = ANSI_BOLD_WHITE;
            break;
        }
    }

    /* Only print colors to a terminal */
    if (!isatty(STDOUT_FILENO)) {
        color_function = "";
        color_fileline = "";
        reset_color    = "";
        magenta_color  = "";
        red_color      = "";
        cyan_color     = "";
    }

    va_start( args, format );

    printf("~ %s%2lu.%lu%s %s[%s%s%s|%s:%-3i%s] %s%s()%s ",
           cyan_color, (tv.tv_sec - mk_core_init_time),
           tv.tv_usec, reset_color,
           magenta_color, color_component, component, color_fileline, file,
           line, magenta_color,
           color_function, function, red_color);
    vprintf(format, args );
    va_end(args);
    printf("%s\n", reset_color);
    fflush(stdout);

    /* Mutex unlock */
    pthread_mutex_unlock(&mutex_trace);
}

int mk_utils_print_errno(int n)
{
        switch(n) {
        case EAGAIN:
            MK_TRACE("EAGAIN");
            return -1;
        case EBADF:
            MK_TRACE("EBADF");
            return -1;
        case EFAULT:
            MK_TRACE("EFAULT");
            return -1;
        case EFBIG:
            MK_TRACE("EFBIG");
            return -1;
        case EINTR:
            MK_TRACE("EINTR");
            return -1;
        case EINVAL:
            MK_TRACE("EINVAL");
            return -1;
        case EPIPE:
            MK_TRACE("EPIPE");
            return -1;
        default:
            MK_TRACE("DONT KNOW");
            return 0;
        }

        return 0;
}
#endif

void mk_print(int type, const char *format, ...)
{
    time_t now;
    struct tm *current;

    const char *header_color = NULL;
    const char *header_title = NULL;
    const char *bold_color = ANSI_BOLD;
    const char *reset_color = ANSI_RESET;
    const char *white_color = ANSI_WHITE;
    va_list args;

    va_start(args, format);

    switch (type) {
    case MK_INFO:
        header_title = "Info";
        header_color = ANSI_GREEN;
        break;
    case MK_ERR:
        header_title = "Error";
        header_color = ANSI_RED;
        break;
    case MK_WARN:
        header_title = "Warning";
        header_color = ANSI_YELLOW;
        break;
    case MK_BUG:
#ifdef DEBUG
        mk_utils_stacktrace();
#endif
        header_title = " BUG !";
        header_color = ANSI_BOLD ANSI_RED;
        break;
    }

    /* Only print colors to a terminal */
    if (!isatty(STDOUT_FILENO)) {
        header_color = "";
        bold_color = "";
        reset_color = "";
        white_color = "";
    }

    now = time(NULL);
    struct tm result;
    current = localtime_r(&now, &result);
    printf("%s[%s%i/%02i/%02i %02i:%02i:%02i%s]%s ",
           bold_color, reset_color,
           current->tm_year + 1900,
           current->tm_mon + 1,
           current->tm_mday,
           current->tm_hour,
           current->tm_min,
           current->tm_sec,
           bold_color, reset_color);

    printf("%s[%s%7s%s]%s ",
           bold_color, header_color, header_title, white_color, reset_color);

    vprintf(format, args);
    va_end(args);
    printf("%s\n", reset_color);
    fflush(stdout);
}

int mk_core_init()
{
    mk_core_init_time = time(NULL);
    return 0;
}
