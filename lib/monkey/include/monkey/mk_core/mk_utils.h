/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#ifndef MK_CORE_UTILS_H
#define MK_CORE_UTILS_H

#include "mk_macros.h"

#include <string.h>
#include <errno.h>

#include "mk_pthread.h"

/* Trace definitions */
#ifdef MK_HAVE_TRACE

#define MK_TRACE_CORE 0
#define MK_TRACE_PLUGIN 1
#define MK_TRACE_COMP_CORE "mk"

#define MK_TRACE(...) mk_utils_trace(MK_TRACE_COMP_CORE, MK_TRACE_CORE, \
                                     __FUNCTION__, __FILENAME__, __LINE__, __VA_ARGS__)

#else

#ifdef MK_TRACE
#undef MK_TRACE
#endif

#define MK_TRACE(...) do {} while (0)
#endif

void mk_print(int type, const char *format, ...) PRINTF_WARNINGS(2,3);

#ifdef MK_HAVE_TRACE
void mk_utils_trace(const char *component, int color, const char *function,
                    char *file, int line, const char* format, ...);
int mk_utils_print_errno(int n);
#endif


/* Thread key to hold a re-entrant buffer for strerror formatting */
#define MK_UTILS_ERROR_SIZE          128
extern pthread_key_t mk_utils_error_key;

/* Windows don't have strerror_r, instead it have strerror_s */
#ifdef _WIN32
  /* Reset as this is defined by mk_pthread.h */
  #ifdef strerror_r
    #undef strerror_r
  #endif
  #define strerror_r(errno, buf, len) strerror_s(buf, len, errno)
#elif !defined(__APPLE__) && !defined(__unix__)
  #ifdef __cplusplus
    extern "C"
      {
  #endif
    extern int __xpg_strerror_r(int errcode,char* buffer,size_t length);
    #define strerror_r __xpg_strerror_r
  #ifdef __cplusplus
      }
  #endif
#endif

/*
 * Helpers to format and print out common errno errors, we use thread
 * keys to hold a buffer per thread so strerror_r(2) can be used without
 * a memory allocation.
 */
#define MK_UTILS_LIBC_ERRNO_BUFFER()                                    \
    int _err  = errno;                                                  \
    char bufs[256];                                                     \
    char *buf = (char *) pthread_getspecific(mk_utils_error_key);       \
    if (!buf) buf = bufs;                                               \
    if (strerror_r(_err, buf, MK_UTILS_ERROR_SIZE) != 0) {              \
        mk_err("strerror_r() failed");                                  \
    }

static inline void mk_utils_libc_error(char *caller, char *file, int line)
{
    MK_UTILS_LIBC_ERRNO_BUFFER();
    mk_err("%s: %s, errno=%i at %s:%i", caller, buf, _err, file, line);
}

static inline void mk_utils_libc_warn(char *caller, char *file, int line)
{
    MK_UTILS_LIBC_ERRNO_BUFFER();
    mk_warn("%s: %s, errno=%i at %s:%i", caller, buf, _err, file, line);
}

int mk_utils_worker_spawn(void (*func) (void *), void *arg, pthread_t *tid);
int mk_utils_worker_rename(const char *title);

#ifndef _WIN32
int mk_utils_set_daemon();
int mk_utils_register_pid(char *path);
int mk_utils_remove_pid(char *path);
#endif

int mk_core_init();

#endif
