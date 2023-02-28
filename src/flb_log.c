/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

static inline int consume_byte(flb_pipefd_t fd)
{
    int ret;
    uint64_t val;

    /* We need to consume the byte */
    ret = flb_pipe_r(fd, &val, sizeof(val));
    if (ret <= 0) {
        flb_errno();
        return -1;
    }

    return 0;
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
        flb_errno();
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
                consume_byte(event->fd);
                run = FLB_FALSE;
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
        close(worker->log[0]);
        close(worker->log[1]);
        return -1;
    }

    /* Log cache to reduce noise */
    cache = flb_log_cache_create(10, FLB_LOG_CACHE_ENTRIES);
    if (!cache) {
        close(worker->log[0]);
        close(worker->log[1]);
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
    time_t now;
    const char *header_color = NULL;
    const char *header_title = NULL;
    const char *bold_color = ANSI_BOLD;
    const char *reset_color = ANSI_RESET;
    struct tm result;
    struct tm *current;

    switch (type) {
    case FLB_LOG_HELP:
        header_title = "help";
        header_color = ANSI_CYAN;
        break;
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
    case FLB_LOG_IDEBUG:
        header_title = "debug";
        header_color = ANSI_CYAN;
        break;
    case FLB_LOG_TRACE:
        header_title = "trace";
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

    now = time(NULL);
    current = localtime_r(&now, &result);

    if (current == NULL) {
        return -1;
    }

    len = snprintf(msg->msg, sizeof(msg->msg) - 1,
                   "%s[%s%i/%02i/%02i %02i:%02i:%02i%s]%s [%s%5s%s] ",
                   /*      time     */                    /* type */

                   /* time variables */
                   bold_color, reset_color,
                   current->tm_year + 1900,
                   current->tm_mon + 1,
                   current->tm_mday,
                   current->tm_hour,
                   current->tm_min,
                   current->tm_sec,
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

    struct flb_worker *w;

    va_start(args, fmt);
    ret = flb_log_construct(&msg, &len, type, file, line, fmt, &args);
    va_end(args);

    if (ret < 0) {
        return;
    }

    w = flb_worker_get();
    if (w) {
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
    return 0;
}

int flb_log_destroy(struct flb_log *log, struct flb_config *config)
{
    uint64_t val = FLB_TRUE;

    /* Signal the child worker, stop working */
    flb_pipe_w(log->ch_mng[1], &val, sizeof(val));
    pthread_join(log->tid, NULL);

    /* Release resources */
    mk_event_loop_destroy(log->evl);
    flb_pipe_destroy(log->ch_mng);
    if (log->worker->log_cache) {
        flb_log_cache_destroy(log->worker->log_cache);
    }
    flb_free(log->worker);
    flb_free(log);

    return 0;
}
