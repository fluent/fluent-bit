/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_sds.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <inttypes.h>
#include <errno.h>
#include <stdarg.h>

/* FIXME: this extern should be auto-populated from flb_thread_storage.h */
extern FLB_TLS_DEFINE(struct flb_log, flb_log_ctx)

/* Message types */
#define FLB_LOG_OFF     0
#define FLB_LOG_ERROR   1
#define FLB_LOG_WARN    2
#define FLB_LOG_INFO    3  /* default */
#define FLB_LOG_DEBUG   4
#define FLB_LOG_TRACE   5
#define FLB_LOG_HELP    6  /* unused by log level */

#define FLB_LOG_IDEBUG  10

/* Logging outputs */
#define FLB_LOG_STDERR   0  /* send logs to STDERR         */
#define FLB_LOG_FILE     1  /* write logs to a file        */
#define FLB_LOG_SOCKET   2  /* write logs to a unix socket */

#define FLB_LOG_EVENT    MK_EVENT_NOTIFICATION
#define FLB_LOG_MNG      1024


#define FLB_LOG_MNG_TERMINATION_SIGNAL 1
#define FLB_LOG_MNG_REFRESH_SIGNAL     2


#define FLB_LOG_CACHE_ENTRIES        10
#define FLB_LOG_CACHE_TEXT_BUF_SIZE  1024

/* Logging main context */
struct flb_log {
    struct mk_event event;     /* worker event for manager */
    flb_pipefd_t ch_mng[2];    /* worker channel manager   */
    uint16_t type;             /* log type                 */
    uint16_t level;            /* level                    */
    char *out;                 /* FLB_LOG_FILE or FLB_LOG_SOCKET */
    pthread_t tid;             /* thread ID   */
    uint64_t next_hb_ns;       /* next heartbeat (nano sec) */
    uint64_t hb_interval_ns;   /* heartbeat interval (nano sec) */
    struct flb_worker *worker; /* non-real worker reference */
    struct mk_event_loop *evl;
    struct flb_log_metrics *metrics;

    /* Initialization variables */
    int pth_init;
    pthread_cond_t  pth_cond;
    pthread_mutex_t pth_mutex;
};

struct flb_log_cache_entry {
    flb_sds_t buf;
    uint64_t timestamp;
    struct mk_list _head;
};

/* Structure to keep a reference of the last N number of entries */
struct flb_log_cache {
    int size;                       /* cache size       */
    int timeout;                    /* cache timeout    */
    struct mk_list entries;         /* list for entries */
};

/* Global metrics for logging calls. */
struct flb_log_metrics {
    struct cmt *cmt;

    /* cmetrics */
    struct cmt_counter *logs_total_counter; /* total number of logs (by message type) */
};

/*
 * This function is used by plugins interface to check if an incoming log message
 * should be logged or not based in the log levels defined.
 */
static inline int flb_log_check_level(int level_set, int msg_level)
{
    if (msg_level <= level_set) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

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

struct flb_log *flb_log_create(struct flb_config *config, int type,
                               int level, char *out);
int flb_log_set_level(struct flb_config *config, int level);
int flb_log_get_level_str(char *str);

int flb_log_set_file(struct flb_config *config, char *out);

int flb_log_destroy(struct flb_log *log, struct flb_config *config);
void flb_log_print(int type, const char *file, int line, const char *fmt, ...) FLB_FORMAT_PRINTF(4, 5);
int flb_log_is_truncated(int type, const char *file, int line, const char *fmt, ...) FLB_FORMAT_PRINTF(4, 5);

struct flb_log_cache *flb_log_cache_create(int timeout_seconds, int size);
void flb_log_cache_destroy(struct flb_log_cache *cache);
struct flb_log_cache_entry *flb_log_cache_exists(struct flb_log_cache *cache, char *msg_buf, size_t msg_size);
struct flb_log_cache_entry *flb_log_cache_get_target(struct flb_log_cache *cache, uint64_t ts);

int flb_log_cache_check_suppress(struct flb_log_cache *cache, char *msg_buf, size_t msg_size);


static inline int flb_log_suppress_check(int log_suppress_interval, const char *fmt, ...)
{
    int ret;
    size_t size;
    va_list args;
    char buf[4096];
    struct flb_worker *w;

    if (log_suppress_interval <= 0) {
        return FLB_FALSE;
    }

    va_start(args, fmt);
    size = vsnprintf(buf, sizeof(buf) - 1, fmt, args);
    va_end(args);

    if (size == -1) {
        return FLB_FALSE;
    }

    w = flb_worker_get();
    if (!w) {
        return FLB_FALSE;
    }

    ret = flb_log_cache_check_suppress(w->log_cache, buf, size);
    return ret;
}


/* Logging macros */
#define flb_helper(fmt, ...)                                    \
    flb_log_print(FLB_LOG_HELP, NULL, 0, fmt, ##__VA_ARGS__)

#define flb_error(fmt, ...)                                          \
    if (flb_log_check(FLB_LOG_ERROR))                                \
        flb_log_print(FLB_LOG_ERROR, NULL, 0, fmt, ##__VA_ARGS__)

#define flb_error_is_truncated(fmt, ...)                                   \
    flb_log_check(FLB_LOG_ERROR)                                           \
        ? flb_log_is_truncated(FLB_LOG_ERROR, NULL, 0, fmt, ##__VA_ARGS__) \
        : 0

#define flb_warn(fmt, ...)                                           \
    if (flb_log_check(FLB_LOG_WARN))                                 \
        flb_log_print(FLB_LOG_WARN, NULL, 0, fmt, ##__VA_ARGS__)

#define flb_warn_is_truncated(fmt, ...     )                              \
    flb_log_check(FLB_LOG_WARN)                                           \
        ? flb_log_is_truncated(FLB_LOG_WARN, NULL, 0, fmt, ##__VA_ARGS__) \
        : 0

#define flb_info(fmt, ...)                                           \
    if (flb_log_check(FLB_LOG_INFO))                                 \
        flb_log_print(FLB_LOG_INFO, NULL, 0, fmt, ##__VA_ARGS__)

#define flb_info_is_truncated(fmt, ...)                                   \
    flb_log_check(FLB_LOG_INFO)                                           \
        ? flb_log_is_truncated(FLB_LOG_INFO, NULL, 0, fmt, ##__VA_ARGS__) \
        : 0

#define flb_debug(fmt, ...)                                         \
    if (flb_log_check(FLB_LOG_DEBUG))                               \
        flb_log_print(FLB_LOG_DEBUG, NULL, 0, fmt, ##__VA_ARGS__)

#define flb_debug_is_truncated(fmt, ...       )                            \
    flb_log_check(FLB_LOG_DEBUG)                                           \
        ? flb_log_is_truncated(FLB_LOG_DEBUG, NULL, 0, fmt, ##__VA_ARGS__) \
        : 0

#define flb_idebug(fmt, ...)                                        \
    flb_log_print(FLB_LOG_IDEBUG, NULL, 0, fmt, ##__VA_ARGS__)

#define flb_idebug_is_truncated(fmt, ...)                           \
    flb_log_is_truncated(FLB_LOG_IDEBUG, NULL, 0, fmt, ##__VA_ARGS__)

#ifdef FLB_HAVE_TRACE
#define flb_trace(fmt, ...)                                             \
    if (flb_log_check(FLB_LOG_TRACE))                                   \
        flb_log_print(FLB_LOG_TRACE, __FILE__, __LINE__,                \
                      fmt, ##__VA_ARGS__)

#define flb_trace_is_truncated(fmt, ...)                           \
    flb_log_check(FLB_LOG_TRACE)                                   \
        ? flb_log_is_truncated(FLB_LOG_TRACE, __FILE__, __LINE__,  \
                      fmt, ##__VA_ARGS__)                          \
        : 0
#else
#define flb_trace(fmt, ...)  do {} while(0)
#define flb_trace_is_truncated(fmt, ...)  do {} while(0)
#endif

int flb_log_worker_init(struct flb_worker *worker);
int flb_log_worker_destroy(struct flb_worker *worker);
int flb_errno_print(int errnum, const char *file, int line);
#ifdef WIN32
int flb_wsa_get_last_error_print(int errnum, const char *file, int line);
#endif

#ifdef __FLB_FILENAME__
#define flb_errno() flb_errno_print(errno, __FLB_FILENAME__, __LINE__)
#ifdef WIN32
#define flb_wsa_get_last_error() flb_wsa_get_last_error_print(WSAGetLastError(), __FLB_FILENAME__, __LINE__)
#endif
#else
#define flb_errno() flb_errno_print(errno, __FILE__, __LINE__)
#ifdef WIN32
#define flb_wsa_get_last_error() flb_wsa_get_last_error_print(WSAGetLastError(), __FILE__, __LINE__)
#endif
#endif

#endif
