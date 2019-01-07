/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_LOG_H
#define FLB_LOG_H

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_thread_storage.h>
#include <fluent-bit/flb_worker.h>
#include <fluent-bit/flb_config.h>
#include <inttypes.h>
#include <errno.h>

/* FIXME: this extern should be auto-populated from flb_thread_storage.h */
extern FLB_TLS_DEFINE(struct flb_log, flb_log_ctx)

/* Message types */
#define FLB_LOG_OFF     0
#define FLB_LOG_ERROR   1
#define FLB_LOG_WARN    2
#define FLB_LOG_INFO    3  /* default */
#define FLB_LOG_DEBUG   4
#define FLB_LOG_TRACE   5

/* Logging outputs */
#define FLB_LOG_STDERR   0  /* send logs to STDERR         */
#define FLB_LOG_FILE     1  /* write logs to a file        */
#define FLB_LOG_SOCKET   2  /* write logs to a unix socket */

#define FLB_LOG_EVENT    MK_EVENT_NOTIFICATION
#define FLB_LOG_MNG      1024

/* Logging main context */
struct flb_log {
    struct mk_event event;     /* worker event for manager */
    flb_pipefd_t ch_mng[2];    /* worker channel manager   */
    uint16_t type;             /* log type                 */
    uint16_t level;            /* level                    */
    char *out;                 /* FLB_LOG_FILE or FLB_LOG_SOCKET */
    pthread_t tid;             /* thread ID   */
    struct flb_worker *worker; /* non-real worker reference */
    struct mk_event_loop *evl;
};

static inline int flb_log_check(int l) {
    struct flb_worker *w;
    w = (struct flb_worker *) FLB_TLS_GET(flb_worker_ctx);
    if (!w && l <= 3) {
        return FLB_TRUE;
    }

    if (w == NULL || flb_worker_log_level(w) < l) {
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

struct flb_log *flb_log_init(struct flb_config *config, int type,
                             int level, char *out);
int flb_log_set_level(struct flb_config *config, int level);
int flb_log_set_file(struct flb_config *config, char *out);

int flb_log_stop(struct flb_log *log, struct flb_config *config);
void flb_log_print(int type, const char *file, int line, const char *fmt, ...);

/* Logging macros */
#define flb_error(fmt, ...)                                          \
    if (flb_log_check(FLB_LOG_ERROR))                                \
        flb_log_print(FLB_LOG_ERROR, NULL, 0, fmt, ##__VA_ARGS__)

#define flb_warn(fmt, ...)                                           \
    if (flb_log_check(FLB_LOG_WARN))                                 \
        flb_log_print(FLB_LOG_WARN, NULL, 0, fmt, ##__VA_ARGS__)

#define flb_info(fmt, ...)                                           \
    if (flb_log_check(FLB_LOG_INFO))                                 \
        flb_log_print(FLB_LOG_INFO, NULL, 0, fmt, ##__VA_ARGS__)

#define flb_debug(fmt, ...)                                         \
    if (flb_log_check(FLB_LOG_DEBUG))                               \
        flb_log_print(FLB_LOG_DEBUG, NULL, 0, fmt, ##__VA_ARGS__)

#ifdef FLB_HAVE_TRACE
#define flb_trace(fmt, ...)                                             \
    if (flb_log_check(FLB_LOG_TRACE))                                   \
        flb_log_print(FLB_LOG_TRACE, __FILE__, __LINE__,                \
                      fmt, ##__VA_ARGS__)
#else
#define flb_trace(fmt, ...)  do {} while(0)
#endif

int flb_log_worker_init(void *data);
int flb_errno_print(int errnum, const char *file, int line);

#ifdef __FILENAME__
#define flb_errno() flb_errno_print(errno, __FILENAME__, __LINE__)
#else
#define flb_errno() flb_errno_print(errno, __FILE__, __LINE__)
#endif

#endif
