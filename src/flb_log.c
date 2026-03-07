/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <signal.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_worker.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>

#ifdef WIN32
#include <winsock.h>
#include <winbase.h>
#endif

#ifdef FLB_HAVE_AWS_ERROR_REPORTER
#include <fluent-bit/aws/flb_aws_error_reporter.h>

extern struct flb_aws_error_reporter *error_reporter;
#endif

FLB_TLS_DEFINE(struct flb_log, flb_log_ctx)

/* Simple structure to dispatch messages to the log collector */
struct log_message {
    size_t size;
    char   msg[4096 - sizeof(size_t)];
};

static inline int64_t flb_log_consume_signal(struct flb_log *context)
{
    int64_t signal_value;
    int     result;

    result = flb_pipe_r(context->ch_mng[0],
                        &signal_value,
                        sizeof(signal_value));

    if (result <= 0) {
        flb_pipe_error();

        return -1;
    }

    return signal_value;
}

static inline int flb_log_enqueue_signal(struct flb_log *context,
                                         int64_t signal_value)
{
    int result;

    result = flb_pipe_w(context->ch_mng[1],
                        &signal_value,
                        sizeof(signal_value));

    if (result <= 0) {
        flb_pipe_error();

        result = 1;
    }
    else {
        result = 0;
    }

    return result;
}

static inline int log_push(struct log_message *msg, struct flb_log *log)
{
    int fd;
    int ret = -1;

    if (log->type == FLB_LOG_STDERR) {
        return write(STDERR_FILENO, msg->msg, msg->size);
    }
    else if (log->type == FLB_LOG_FILE) {
        fd = open(log->out, O_CREAT | O_WRONLY | O_APPEND, 0666);
        if (fd == -1) {
            fprintf(stderr, "[log] error opening log file %s. Using stderr.\n",
                    log->out);
            return write(STDERR_FILENO, msg->msg, msg->size);
        }
        ret = write(fd, msg->msg, msg->size);
        close(fd);
    }

    return ret;
}

static inline int log_read(flb_pipefd_t fd, struct flb_log *log)
{
    int bytes;
    struct log_message msg;

    /*
     * Since write operations to the pipe are always atomic 'if' they are
     * under the PIPE_BUF limit (4KB on Linux) and our messages are always 1KB,
     * we can trust we will always get a full message on each read(2).
     */
    bytes = flb_pipe_read_all(fd, &msg, sizeof(struct log_message));

    if (bytes <= 0) {
        return -1;
    }
    if (msg.size > sizeof(msg.msg)) {
        fprintf(stderr, "[log] message too long: %zi > %zi",
                msg.size, sizeof(msg.msg));

        return -1;
    }

    log_push(&msg, log);

    return bytes;
}

/* Central collector of messages */
static void log_worker_collector(void *data)
{
    int run = FLB_TRUE;
    struct mk_event *event = NULL;
    struct flb_log *log = data;
    int64_t signal_value;

    FLB_TLS_INIT(flb_log_ctx);
    FLB_TLS_SET(flb_log_ctx, log);

    mk_utils_worker_rename("flb-logger");

    /* Signal the caller */
    pthread_mutex_lock(&log->pth_mutex);
    log->pth_init = FLB_TRUE;
    pthread_cond_signal(&log->pth_cond);
    pthread_mutex_unlock(&log->pth_mutex);

    while (run) {
        mk_event_wait(log->evl);

        mk_event_foreach(event, log->evl) {
            if (event->type == FLB_LOG_EVENT) {
                log_read(event->fd, log);
            }
            else if (event->type == FLB_LOG_MNG) {
                signal_value = flb_log_consume_signal(log);

                if (signal_value == FLB_LOG_MNG_TERMINATION_SIGNAL) {
                    run = FLB_FALSE;
                }
                else if (signal_value == FLB_LOG_MNG_REFRESH_SIGNAL) {
                    /* This signal is only used to
                     * break the loop when a new client is
                     * added in order to prevent a deadlock
                     * that happens if the newly added pipes capacity
                     * is exceeded during the initialization process
                     * of a threaded input plugin which causes write
                     * to block (until the logger thread consumes
                     * the buffered data) which in turn keeps the
                     * thread from triggering the status set
                     * condition which causes the main thread to
                     * lock indefinitely as described in issue 9667.
                     */
                }
            }
        }
    }

    pthread_exit(NULL);
}

struct flb_log_cache *flb_log_cache_create(int timeout_seconds, int size)
{
    int i;
    struct flb_log_cache *cache;
    struct flb_log_cache_entry *entry;

    if (size <= 0) {
        return NULL;
    }

    cache = flb_calloc(1, sizeof(struct flb_log_cache));
    if (!cache) {
        flb_errno();
        return NULL;
    }
    cache->timeout = timeout_seconds;
    mk_list_init(&cache->entries);

    for (i = 0; i < size; i++) {
        entry = flb_calloc(1, sizeof(struct flb_log_cache_entry));
        if (!entry) {
            flb_errno();
            flb_log_cache_destroy(cache);
            return NULL;
        }

        entry->buf = flb_sds_create_size(FLB_LOG_CACHE_TEXT_BUF_SIZE);
        if (!entry->buf) {
            flb_errno();
            flb_log_cache_destroy(cache);
        }
        entry->timestamp = 0; /* unset for now */
        mk_list_add(&entry->_head, &cache->entries);
    }

    return cache;
}

void flb_log_cache_destroy(struct flb_log_cache *cache)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_log_cache_entry *entry;

    if (!cache) {
        return;
    }

    mk_list_foreach_safe(head, tmp, &cache->entries) {
        entry = mk_list_entry(head, struct flb_log_cache_entry, _head);
        flb_sds_destroy(entry->buf);
        mk_list_del(&entry->_head);
        flb_free(entry);
    }
    flb_free(cache);
}

struct flb_log_cache_entry *flb_log_cache_exists(struct flb_log_cache *cache, char *msg_buf, size_t msg_size)
{
    size_t size;
    struct mk_list *head;
    struct flb_log_cache_entry *entry;

    if (msg_size <= 1) {
        return NULL;
    }

    /* number of bytes to compare */
    size = msg_size / 2;

    mk_list_foreach(head, &cache->entries) {
        entry = mk_list_entry(head, struct flb_log_cache_entry, _head);
        if (entry->timestamp == 0) {
            continue;
        }

        if (flb_sds_len(entry->buf) < size) {
            continue;
        }

        if (strncmp(entry->buf, msg_buf, size) == 0) {
            return entry;
        }
    }

    return NULL;
}


/* returns an unused entry or the oldest one */
struct flb_log_cache_entry *flb_log_cache_get_target(struct flb_log_cache *cache, uint64_t ts)
{
    struct mk_list *head;
    struct flb_log_cache_entry *entry;
    struct flb_log_cache_entry *target = NULL;

    mk_list_foreach(head, &cache->entries) {
        entry = mk_list_entry(head, struct flb_log_cache_entry, _head);

        /* unused entry */
        if (entry->timestamp == 0) {
            return entry;
        }

        /* expired entry */
        if (entry->timestamp + cache->timeout < ts) {
            return entry;
        }

        /* keep a reference to the oldest entry to sacrifice it */
        if (!target || entry->timestamp < target->timestamp) {
            target = entry;
        }
    }

    return target;
}

/*
 * should the incoming message to be suppressed because already one similar exists in
 * the cache ?
 *
 * if no similar message exists, then the incoming message is added to the cache.
 */
int flb_log_cache_check_suppress(struct flb_log_cache *cache, char *msg_buf, size_t msg_size)
{
    uint64_t now = 0;
    struct flb_log_cache_entry *entry;

    now = time(NULL);
    entry = flb_log_cache_exists(cache, msg_buf, msg_size);

    /* if no similar message found, add the incoming message to the cache */
    if (!entry) {
        /* look for an unused entry or the oldest one */
        entry = flb_log_cache_get_target(cache, now);

        /* if no target entry is available just return, do not suppress the message */
        if (!entry) {
            return FLB_FALSE;
        }

        /* add the message to the cache */
        flb_sds_len_set(entry->buf, 0);
        entry->buf = flb_sds_copy(entry->buf, msg_buf, msg_size);
        entry->timestamp = now;
        return FLB_FALSE;
    }
    else {
        if (entry->timestamp + cache->timeout > now) {
            return FLB_TRUE;
        }
        else {
            entry->timestamp = now;
            return FLB_FALSE;
        }
    }
    return FLB_TRUE;
}

int flb_log_worker_destroy(struct flb_worker *worker)
{
    flb_pipe_destroy(worker->log);
    return 0;
}

int flb_log_worker_init(struct flb_worker *worker)
{
    int ret;
    struct flb_config *config = worker->config;
    struct flb_log *log = config->log;
    struct flb_log_cache *cache;

    /* Pipe to communicate Thread with worker log-collector */
    ret = flb_pipe_create(worker->log);
    if (ret == -1) {
        flb_errno();
        return -1;
    }

    /* Register the read-end of the pipe (log[0]) into the event loop */
    ret = mk_event_add(log->evl, worker->log[0],
                       FLB_LOG_EVENT, MK_EVENT_READ, &worker->event);

    if (ret == -1) {
        flb_pipe_destroy(worker->log);

        return -1;
    }

    ret = flb_log_enqueue_signal(log, FLB_LOG_MNG_REFRESH_SIGNAL);

    if (ret == -1) {
        mk_event_del(log->evl, &worker->event);

        flb_pipe_destroy(worker->log);

        return -1;
    }

    /* Log cache to reduce noise */
    cache = flb_log_cache_create(10, FLB_LOG_CACHE_ENTRIES);
    if (!cache) {
        mk_event_del(log->evl, &worker->event);

        flb_pipe_destroy(worker->log);

        return -1;
    }

    worker->log_cache = cache;

    return 0;
}

int flb_log_set_level(struct flb_config *config, int level)
{
    config->log->level = level;
    return 0;
}

int flb_log_get_level_str(char *str)
{
    if (strcasecmp(str, "off") == 0) {
        return FLB_LOG_OFF;
    }
    else if (strcasecmp(str, "error") == 0) {
        return FLB_LOG_ERROR;
    }
    else if (strcasecmp(str, "warn") == 0 || strcasecmp(str, "warning") == 0) {
        return FLB_LOG_WARN;
    }
    else if (strcasecmp(str, "info") == 0) {
        return FLB_LOG_INFO;
    }
    else if (strcasecmp(str, "debug") == 0) {
        return FLB_LOG_DEBUG;
    }
    else if (strcasecmp(str, "trace") == 0) {
        return FLB_LOG_TRACE;
    }

    return -1;
}

static inline const char *flb_log_message_type_str(int type)
{
    switch (type) {
    case FLB_LOG_HELP:
        return "help";
    case FLB_LOG_INFO:
        return "info";
    case FLB_LOG_WARN:
        return "warn";
    case FLB_LOG_ERROR:
        return "error";
    case FLB_LOG_DEBUG:
        return "debug";
    case FLB_LOG_IDEBUG:
        return "debug";
    case FLB_LOG_TRACE:
        return "trace";
    default:
        return NULL;
    }
}

int flb_log_set_file(struct flb_config *config, char *out)
{
    struct flb_log *log = config->log;

    if (out) {
        log->type = FLB_LOG_FILE;
        log->out = out;
    }
    else {
        log->type = FLB_LOG_STDERR;
        log->out = NULL;
    }

    return 0;
}

/* Frees the metrics instance and its associated resources. */
void flb_log_metrics_destroy(struct flb_log_metrics *metrics)
{
    if (metrics == NULL) {
        return;
    }
    if (metrics->cmt != NULL) {
        cmt_destroy(metrics->cmt);
    }
    flb_free(metrics);
}

/*
 * Create and register cmetrics for the runtime logger.
 * The caller must free the returned struct using flb_log_metrics_destroy.
 */
struct flb_log_metrics *flb_log_metrics_create()
{
    struct flb_log_metrics *metrics;
    int log_message_type;
    const char *message_type_str;
    uint64_t ts;
    int ret;

    metrics = flb_calloc(1, sizeof(struct flb_log_metrics));
    if (metrics == NULL) {
        flb_errno();
        return NULL;
    }

    metrics->cmt = cmt_create();
    if (metrics->cmt == NULL) {
        flb_log_metrics_destroy(metrics);
        return NULL;
    }

    metrics->logs_total_counter = cmt_counter_create(metrics->cmt,
                                                     "fluentbit",
                                                     "logger",
                                                     "logs_total",
                                                     "Total number of logs",
                                                     1, (char *[]) {"message_type"});
    if (metrics->logs_total_counter == NULL) {
        flb_log_metrics_destroy(metrics);
        return NULL;
    }

    /* Initialize counters for log message types to 0. */
    ts = cfl_time_now();
    for (log_message_type = FLB_LOG_ERROR; log_message_type <= FLB_LOG_TRACE; log_message_type++) {
        message_type_str = flb_log_message_type_str(log_message_type);
        if (!message_type_str) {
            break;
        }

        ret = cmt_counter_set(metrics->logs_total_counter,
                              ts,
                              0,
                              1, (char *[]) {(char *) message_type_str});
        if (ret == -1) {
            flb_log_metrics_destroy(metrics);
            return NULL;
        }
    }

    return metrics;
}

struct flb_log *flb_log_create(struct flb_config *config, int type,
                               int level, char *out)
{
    int ret;
    struct flb_log *log;
    struct flb_worker *worker;
    struct mk_event_loop *evl;

    log = flb_calloc(1, sizeof(struct flb_log));
    if (!log) {
        flb_errno();
        return NULL;
    }
    config->log = log;

    /* Create event loop to be used by the collector worker */
    evl = mk_event_loop_create(32);
    if (!evl) {
        fprintf(stderr, "[log] could not create event loop\n");
        flb_free(log);
        config->log = NULL;
        return NULL;
    }

    /* Prepare logging context */
    log->type  = type;
    log->level = level;
    log->out   = out;
    log->evl   = evl;
    log->tid   = 0;

    ret = flb_pipe_create(log->ch_mng);
    if (ret == -1) {
        fprintf(stderr, "[log] could not create pipe(2)");
        mk_event_loop_destroy(log->evl);
        flb_free(log);
        config->log = NULL;
        return NULL;
    }
    MK_EVENT_ZERO(&log->event);

    /* Register channel manager into the event loop */
    ret = mk_event_add(log->evl, log->ch_mng[0],
                       FLB_LOG_MNG, MK_EVENT_READ, &log->event);

    if (ret == -1) {
        fprintf(stderr, "[log] could not register event\n");
        mk_event_loop_destroy(log->evl);
        flb_free(log);
        config->log = NULL;
        return NULL;
    }

    /* Create metrics */
    log->metrics = flb_log_metrics_create();
    if (log->metrics == NULL) {
        fprintf(stderr, "[log] could not create log metrics\n");
        mk_event_loop_destroy(log->evl);
        flb_free(log);
        config->log = NULL;
        return NULL;
    }

    /*
     * Since the main process/thread might want to write log messages,
     * it will need a 'worker-like' context, here we create a fake worker
     * context just for messaging purposes.
     */
    worker = flb_worker_context_create(NULL, NULL, config);
    if (!worker) {
        flb_errno();
        mk_event_loop_destroy(log->evl);
        flb_free(log);
        config->log = NULL;
    }

    /* Set the worker context global */
    FLB_TLS_INIT(flb_worker_ctx);
    FLB_TLS_SET(flb_worker_ctx, worker);

    ret = flb_log_worker_init(worker);
    if (ret == -1) {
        flb_errno();
        mk_event_loop_destroy(log->evl);
        flb_free(log);
        config->log = NULL;
        flb_free(worker);
        return NULL;
    }
    log->worker = worker;

    /*
     * This lock is used for the 'pth_cond' conditional. Once the worker
     * thread is ready will signal the condition.
     */
    pthread_mutex_init(&log->pth_mutex, NULL);
    pthread_cond_init(&log->pth_cond, NULL);
    log->pth_init = FLB_FALSE;

    pthread_mutex_lock(&log->pth_mutex);

    ret = flb_worker_create(log_worker_collector, log, &log->tid, config);
    if (ret == -1) {
        pthread_mutex_unlock(&log->pth_mutex);
        mk_event_loop_destroy(log->evl);
        flb_free(log->worker);
        flb_free(log);
        config->log = NULL;
        return NULL;
    }

    /* Block until the child thread is ready */
    while (!log->pth_init) {
        pthread_cond_wait(&log->pth_cond, &log->pth_mutex);
    }
    pthread_mutex_unlock(&log->pth_mutex);

    return log;
}

int flb_log_construct(struct log_message *msg, int *ret_len,
                     int type, const char *file, int line, const char *fmt, va_list *args)
{
    int body_size;
    int ret;
    int len;
    int total;
    const char *header_color = NULL;
    const char *header_title;
    const char *bold_color = ANSI_BOLD;
    const char *reset_color = ANSI_RESET;
    struct tm result;
    struct tm *current;
    struct flb_time now;

    switch (type) {
    case FLB_LOG_HELP:
        header_color = ANSI_CYAN;
        break;
    case FLB_LOG_INFO:
        header_color = ANSI_GREEN;
        break;
    case FLB_LOG_WARN:
        header_color = ANSI_YELLOW;
        break;
    case FLB_LOG_ERROR:
        header_color = ANSI_RED;
        break;
    case FLB_LOG_DEBUG:
        header_color = ANSI_YELLOW;
        break;
    case FLB_LOG_IDEBUG:
        header_color = ANSI_CYAN;
        break;
    case FLB_LOG_TRACE:
        header_color = ANSI_BLUE;
        break;
    }

    #ifdef FLB_LOG_NO_CONTROL_CHARS
    header_color = "";
    bold_color = "";
    reset_color = "";
    #else
    /* Only print colors to a terminal */
    if (!isatty(STDOUT_FILENO)) {
        header_color = "";
        bold_color = "";
        reset_color = "";
    }
    #endif // FLB_LOG_NO_CONTROL_CHARS

    flb_time_get(&now);
    current = localtime_r(&now.tm.tv_sec, &result);

    if (current == NULL) {
        return -1;
    }

    header_title = flb_log_message_type_str(type);
    len = snprintf(msg->msg, sizeof(msg->msg) - 1,
                   "%s[%s%i-%02i-%02i %02i:%02i:%02i.%03ld%s]%s [%s%5s%s] ",
                   /*      time     */                    /* type */

                   /* time variables */
                   bold_color, reset_color,
                   current->tm_year + 1900,
                   current->tm_mon + 1,
                   current->tm_mday,
                   current->tm_hour,
                   current->tm_min,
                   current->tm_sec,
                   now.tm.tv_nsec,
                   bold_color, reset_color,

                   /* type format */
                   header_color, header_title, reset_color);

    body_size = (sizeof(msg->msg) - 2) - len;
    total = vsnprintf(msg->msg + len,
                      body_size,
                      fmt, *args);
    if (total < 0) {
        return -1;
    }
    ret = total; /* ret means a buffer size need to save log body */

    total = strlen(msg->msg + len) + len;
    msg->msg[total++] = '\n';
    msg->msg[total]   = '\0';
    msg->size = total;

    *ret_len = len;

    if (ret >= body_size) {
        /* log is truncated */
        return ret - body_size;
    }

    return 0;
}

/**
 * flb_log_is_truncated tries to construct log and returns that the log is truncated.
 *
 * @param same as flb_log_print
 * @return 0: log is not truncated. -1: some error occurs.
 *         positive number: truncated log size.
 *
 */
int flb_log_is_truncated(int type, const char *file, int line, const char *fmt, ...)
{
    int ret;
    int len;
    struct log_message msg = {0};
    va_list args;

    va_start(args, fmt);
    ret = flb_log_construct(&msg, &len, type, file, line, fmt, &args);
    va_end(args);

    if (ret < 0) {
        return -1;
    }

    return ret;
}

void flb_log_print(int type, const char *file, int line, const char *fmt, ...)
{
    int n;
    int len;
    int ret;
    struct log_message msg = {0};
    va_list args;
    const char *msg_type_str;
    uint64_t ts;

    struct flb_worker *w;
    struct flb_config *config;

    va_start(args, fmt);
    ret = flb_log_construct(&msg, &len, type, file, line, fmt, &args);
    va_end(args);

    if (ret < 0) {
        return;
    }

    w = flb_worker_get();
    if (w) {
        config = w->config;
        if (config != NULL && config->log != NULL) {
            msg_type_str = flb_log_message_type_str(type);
            if (msg_type_str == NULL) {
                msg_type_str = "unknown";
            }

            ts = cfl_time_now();
            ret = cmt_counter_inc(config->log->metrics->logs_total_counter,
                                  ts,
                                  1, (char *[]) {(char *) msg_type_str});
            if (ret == -1) {
                /* Not using flb_log_debug to avoid recursing into this same function. */
                fprintf(stderr,
                        "[log] failed to increment log total counter for message type '%s' (error=%d)\n",
                        msg_type_str, ret);
            }
        }

        n = flb_pipe_write_all(w->log[1], &msg, sizeof(msg));

        if (n == -1) {
            fprintf(stderr, "%s", (char *) msg.msg);
            perror("write");
        }
    }
    else {
        fprintf(stderr, "%s", (char *) msg.msg);
    }

    #ifdef FLB_HAVE_AWS_ERROR_REPORTER
    if (is_error_reporting_enabled()) {
        if (type == FLB_LOG_ERROR) {
            flb_aws_error_reporter_write(error_reporter, msg.msg + len);
        }

        flb_aws_error_reporter_clean(error_reporter);
    }
    #endif
}

int flb_errno_print(int errnum, const char *file, int line)
{
    char buf[256];

    strerror_r(errnum, buf, sizeof(buf) - 1);
    flb_error("[%s:%i errno=%i] %s", file, line, errnum, buf);
    return errnum;
}

#ifdef WIN32
int flb_wsa_get_last_error_print(int errnum, const char *file, int line)
{
    char buf[256];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, errnum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  buf, sizeof(buf), NULL);
    flb_error("[%s:%i WSAGetLastError=%i] %s", file, line, errnum, buf);
    return errnum;
}
#endif

int flb_log_destroy(struct flb_log *log, struct flb_config *config)
{
    /* Signal the child worker, stop working */
    flb_log_enqueue_signal(log, FLB_LOG_MNG_TERMINATION_SIGNAL);

    pthread_join(log->tid, NULL);

    /* Release resources */
    mk_event_loop_destroy(log->evl);
    flb_pipe_destroy(log->ch_mng);
    if (log->worker->log_cache) {
        flb_log_cache_destroy(log->worker->log_cache);
        log->worker->log_cache = NULL;
    }
    flb_log_worker_destroy(log->worker);
    flb_free(log->worker);
    flb_log_metrics_destroy(log->metrics);
    flb_free(log);

    return 0;
}
