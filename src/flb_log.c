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

FLB_TLS_DEFINE(struct flb_log, flb_log_ctx)

/* thread initializator */
static int pth_init;
static pthread_cond_t  pth_cond;
static pthread_mutex_t pth_mutex;

/* Simple structure to dispatch messages to the log collector */
struct log_message {
    size_t size;
    char   msg[1024 - sizeof(size_t)];
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
    bytes = flb_pipe_r(fd, &msg, sizeof(struct log_message));
    if (bytes <= 0) {
        perror("bytes");
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

    FLB_TLS_SET(flb_log_ctx, log);

    /* Signal the caller */
    pthread_mutex_lock(&pth_mutex);
    pth_init = FLB_TRUE;
    pthread_cond_signal(&pth_cond);
    pthread_mutex_unlock(&pth_mutex);

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

int flb_log_worker_init(void *data)
{
    int ret;
    struct flb_worker *worker = data;
    struct flb_config *config = worker->config;
    struct flb_log *log = config->log;

    /* Pipe to communicate Thread with worker log-collector */
    ret = flb_pipe_create(worker->log);
    if (ret == -1) {
        perror("pipe");
        return -1;
    }

    /* Register the read-end of the pipe (log[0]) into the event loop */
    MK_EVENT_ZERO(&worker->event);
    ret = mk_event_add(log->evl, worker->log[0],
                       FLB_LOG_EVENT, MK_EVENT_READ, &worker->event);
    if (ret == -1) {
        close(worker->log[0]);
        close(worker->log[1]);
        return -1;
    }

    return 0;
}

int flb_log_set_level(struct flb_config *config, int level)
{
    config->log->level = level;
    return 0;
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

struct flb_log *flb_log_init(struct flb_config *config, int type,
                             int level, char *out)
{
    int ret;
    struct flb_log *log;
    struct flb_worker *worker;
    struct mk_event_loop *evl;

    log = flb_malloc(sizeof(struct flb_log));
    if (!log) {
        perror("malloc");
        return NULL;
    }
    config->log = log;

    /* Create event loop to be used by the collector worker */
    evl = mk_event_loop_create(16);
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
    worker = flb_malloc(sizeof(struct flb_worker));
    if (!worker) {
        flb_errno();
        mk_event_loop_destroy(log->evl);
        flb_free(log);
        config->log = NULL;
        return NULL;
    }
    worker->func    = NULL;
    worker->data    = NULL;
    worker->log_ctx = log;
    worker->config  = config;

    /* Set the worker context global */
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
    pthread_mutex_init(&pth_mutex, NULL);
    pthread_cond_init(&pth_cond, NULL);
    pth_init = FLB_FALSE;

    pthread_mutex_lock(&pth_mutex);

    ret = flb_worker_create(log_worker_collector, log, &log->tid, config);
    if (ret == -1) {
        pthread_mutex_unlock(&pth_mutex);
        mk_event_loop_destroy(log->evl);
        flb_free(log->worker);
        flb_free(log);
        config->log = NULL;
        return NULL;
    }

    /* Block until the child thread is ready */
    while (!pth_init) {
        pthread_cond_wait(&pth_cond, &pth_mutex);
    }
    pthread_mutex_unlock(&pth_mutex);

    return log;
}

void flb_log_print(int type, const char *file, int line, const char *fmt, ...)
{
    int len;
    int total;
    time_t now;
    const char *header_color = NULL;
    const char *header_title = NULL;
    const char *bold_color = ANSI_BOLD;
    const char *reset_color = ANSI_RESET;
    struct tm result;
    struct tm *current;
    struct log_message msg = {0};
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

    len = snprintf(msg.msg, sizeof(msg.msg) - 1,
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

    total = vsnprintf(msg.msg + len,
                      (sizeof(msg.msg) - 2) - len,
                      fmt, args);
    if (total < 0) {
        return;
    }

    total = strlen(msg.msg + len) + len;
    msg.msg[total++] = '\n';
    msg.msg[total]   = '\0';
    msg.size = total;
    va_end(args);

    struct flb_worker *w;

    w = flb_worker_get();
    if (w) {
        int n = flb_pipe_w(w->log[1], &msg, sizeof(msg));
        if (n == -1) {
            perror("write");
        }
    }
    else {
        fprintf(stderr, "%s", (char *) msg.msg);
    }
}

int flb_errno_print(int errnum, const char *file, int line)
{
    char buf[256];

    strerror_r(errnum, buf, sizeof(buf) - 1);
    flb_error("[%s:%i errno=%i] %s", file, line, errnum, buf);
    return 0;
}

int flb_log_stop(struct flb_log *log, struct flb_config *config)
{
    uint64_t val = FLB_TRUE;

    /* Signal the child worker, stop working */
    flb_pipe_w(log->ch_mng[1], &val, sizeof(val));
    pthread_join(log->tid, NULL);

    /* Release resources */
    mk_event_loop_destroy(log->evl);
    flb_pipe_destroy(log->ch_mng);
    flb_free(log->worker);
    flb_free(log);

    return 0;
}
