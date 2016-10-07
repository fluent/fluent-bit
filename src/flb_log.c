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
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <mk_core.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_worker.h>

FLB_TLS_DEFINE(struct flb_log, flb_log_ctx)

/* thread initializator */
pthread_cond_t  pth_cond;
pthread_mutex_t pth_mutex;

/* Simple structure to dispatch messages to the log collector */
struct log_message {
    size_t size;
    char   msg[1024 - sizeof(size_t)];
};

static inline int log_push(struct log_message *msg)
{
    int fd;
    int ret = -1;
    struct flb_log *log = FLB_TLS_GET(flb_log_ctx);

    if (log->type == FLB_LOG_STDERR) {
        return write(STDERR_FILENO, msg->msg, msg->size);
    }
    else if (log->type == FLB_LOG_FILE) {
        fd = open(log->out, O_CREAT | O_WRONLY | O_APPEND, 0666);
        if (fd == -1) {
            fprintf(stderr, "[log] error opening log file %s\n", log->out);
        }
        ret = write(fd, msg->msg, msg->size);
        close(fd);
    }

    return ret;
}

static inline int log_read(int fd, struct flb_log *log)
{
    int bytes;
    struct log_message msg;

    /*
     * Since write operations to the pipe are always atomic 'if' they are
     * under the PIPE_BUF limit (4KB on Linux) and our messages are always 1KB,
     * we can trust we will always get a full message on each read(2).
     */
    bytes = read(fd, &msg, sizeof(struct log_message));
    if (bytes <= 0) {
        perror("bytes");
        return -1;
    }
    log_push(&msg);

    return bytes;
}

/* Central collector of messages */
static void log_worker_collector(void *data)
{
    struct mk_event *event;
    struct flb_log *log = data;

    FLB_TLS_SET(flb_log_ctx, log);
    pthread_cond_signal(&pth_cond);

    while (1) {
        mk_event_wait(log->evl);
        mk_event_foreach(event, log->evl) {
            if (event->type == FLB_LOG_EVENT) {
                log_read(event->fd, log);
            }
        }
    }
}

int flb_log_worker_init(void *data)
{
    int ret;
    struct flb_worker *worker = data;
    struct flb_config *config = worker->config;
    struct flb_log *log = config->log;

    /* Pipe to communicate Thread with worker log-collector */
    ret = pipe(worker->log);
    if (ret == -1) {
        perror("pipe");
        return -1;
    }

    /* Register the read-end of the pipe (log[0]) into the event loop */
    MK_EVENT_NEW(&worker->event);
    ret = mk_event_add(log->evl, worker->log[0],
                       FLB_LOG_EVENT, MK_EVENT_READ, &worker->event);
    if (ret == -1) {
        close(worker->log[0]);
        close(worker->log[1]);
        return -1;
    }

    return 0;
}

struct flb_log *flb_log_init(int type, int level, char *out)
{
    int ret;
    struct flb_log *log;
    struct mk_event_loop *evl;

    log = malloc(sizeof(struct flb_log));
    if (!log) {
        perror("malloc");
        return NULL;
    }

    /* Create event loop to be used by the collector worker */
    evl = mk_event_loop_create(16);
    if (!evl) {
        fprintf(stderr, "[log] could not create event loop\n");
        free(log);
        return NULL;
    }

    /* Only supporting STDERR for now */
    log->type  = type;
    log->level = level;
    log->out   = out;
    log->evl   = evl;

    /* Initialize and set log context in workers space */
    FLB_TLS_INIT(flb_log_ctx);
    FLB_TLS_SET(flb_log_ctx, log);

    /*
     * This lock is used for the 'pth_cond' conditional. Once the worker
     * thread is ready will signal the condition.
     */
    pthread_mutex_lock(&pth_mutex);

    ret = mk_utils_worker_spawn(log_worker_collector,
                                log, &log->tid);
    if (ret == -1) {
        pthread_mutex_unlock(&pth_mutex);
        mk_event_loop_destroy(log->evl);
        free(log);
        return NULL;
    }

    /* Block until the child thread is ready */
    pthread_cond_wait(&pth_cond, &pth_mutex);
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
    struct log_message msg;
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
                      (sizeof(msg.msg) - 1) - len,
                      fmt, args);
    total += len;
    msg.msg[total++] = '\n';
    msg.msg[total]   = '\0';
    msg.size = total;
    va_end(args);

    struct flb_worker *w;

    w = flb_worker_get();
    if (w) {
        int n = write(w->log[1], &msg, sizeof(msg));
        if (n == -1) {
            perror("write");
        }
    }
    else {
        log_push(&msg);
    }
}

int flb_errno_print(int errnum, const char *file, int line)
{
    char buf[256];

    strerror_r(errnum, buf, sizeof(buf) - 1);
    flb_error("[%s:%i errno=%i] %s", file, line, errnum, buf);
    return 0;
}

int flb_log_stop(struct flb_log *log)
{
    free(log);
    return 0;
}

int flb_log_test(char *msg)
{
    int len;
    struct flb_worker *worker;

    worker = FLB_TLS_GET(flb_worker_ctx);
    if (!worker) {
        printf("no worker!: %s\n", msg);
    }

    len = strlen(msg);
    int n = write(worker->log[1], msg, len);
    printf("write=%i bytes\n", n);
    return n;
}

#ifndef FLB_HAVE_C_TLS
int flb_log_check(int level) {
    struct flb_log *lc = FLB_TLS_GET(flb_log_ctx);

    if (!lc) {
        return FLB_FALSE;
    }

    if (lc->level < level)
        return FLB_FALSE;
    else
        return FLB_TRUE;
}
#endif
