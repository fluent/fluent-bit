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

static int log_queue_enqueue(struct flb_log *log, int type,
                             const struct flb_time *timestamp,
                             const char *msg, size_t size);
static struct flb_log_record *log_queue_dequeue(struct flb_log *log);
static void log_queue_destroy(struct flb_log *log);
static void log_queue_report_drops(struct flb_log *log);
static void log_queue_increment_counter(struct cmt_counter *counter, uint64_t value);
static int log_open_sink(struct flb_log *log);
static void log_close_sink(struct flb_log *log);
static inline const char *flb_log_message_type_str(int type);
static struct flb_log_record *log_queue_pop(struct flb_log_queue *queue);
static void log_queue_cleanup(struct flb_log_queue *queue);
static int log_prepare_header(char *buf, size_t size, int type,
                              const struct flb_time *timestamp);
static int log_render_message(struct log_message *msg, int type,
                              const struct flb_time *timestamp,
                              const char *body, size_t body_size);
static struct flb_log_record *log_record_clone(int type,
                                               const struct flb_time *timestamp,
                                               const char *msg, size_t size);
static int log_pipeline_signal(struct flb_log *log);
static void log_pipeline_mirror(struct flb_log *log, struct flb_log_record *record);

static inline int64_t flb_log_consume_signal(struct flb_log *context)
{
    int64_t signal_value;
    int     ret;

    ret = flb_pipe_r(context->ch_mng[0], &signal_value, sizeof(signal_value));

    if (ret <= 0) {
        flb_pipe_error();

        return -1;
    }

    return signal_value;
}

static inline int flb_log_enqueue_signal(struct flb_log *context,
                                         int64_t signal_value)
{
    int ret;

    ret = flb_pipe_w(context->ch_mng[1], &signal_value, sizeof(signal_value));

    if (ret <= 0) {
        flb_pipe_error();

        ret = 1;
    }
    else {
        ret = 0;
    }

    return ret;
}

static inline int log_push(struct log_message *msg, struct flb_log *log)
{
    int ret = -1;

    if (log->type == FLB_LOG_STDERR) {
        return write(STDERR_FILENO, msg->msg, msg->size);
    }
    else if (log->type == FLB_LOG_FILE) {
        if (log->out_fd == -1 && log_open_sink(log) == -1) {
            return write(STDERR_FILENO, msg->msg, msg->size);
        }
        ret = write(log->out_fd, msg->msg, msg->size);
    }

    return ret;
}

static void log_queue_increment_counter(struct cmt_counter *counter, uint64_t value)
{
    int ret;

    if (counter == NULL || value == 0) {
        return;
    }

    ret = cmt_counter_add(counter, cfl_time_now(), value, 0, NULL);
    if (ret == -1) {
        fprintf(stderr, "[log] failed to update logger transport counter\n");
    }
}

static int log_open_sink(struct flb_log *log)
{
    log->out_fd = open(log->out, O_CREAT | O_WRONLY | O_APPEND, 0666);
    if (log->out_fd == -1) {
        fprintf(stderr, "[log] error opening log file %s. Using stderr.\n",
                log->out);
        return -1;
    }

    return 0;
}

static void log_close_sink(struct flb_log *log)
{
    if (log->out_fd != -1) {
        close(log->out_fd);
        log->out_fd = -1;
    }
}

static int log_prepare_header(char *buf, size_t size, int type,
                              const struct flb_time *timestamp)
{
    const char *header_color = NULL;
    const char *header_title;
    const char *bold_color = ANSI_BOLD;
    const char *reset_color = ANSI_RESET;
    struct tm tm_result;
    struct tm *current;

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
    if (!isatty(STDERR_FILENO)) {
        header_color = "";
        bold_color = "";
        reset_color = "";
    }
#endif

    current = localtime_r(&timestamp->tm.tv_sec, &tm_result);
    if (current == NULL) {
        return -1;
    }

    header_title = flb_log_message_type_str(type);

    return snprintf(buf, size,
                    "%s[%s%i/%02i/%02i %02i:%02i:%02i.%03ld%s]%s [%s%5s%s] ",
                    bold_color, reset_color,
                    current->tm_year + 1900,
                    current->tm_mon + 1,
                    current->tm_mday,
                    current->tm_hour,
                    current->tm_min,
                    current->tm_sec,
                    (long) (timestamp->tm.tv_nsec / 1000000),
                    bold_color, reset_color,
                    header_color, header_title, reset_color);
}

static int log_render_message(struct log_message *msg, int type,
                              const struct flb_time *timestamp,
                              const char *body, size_t body_size)
{
    int header_length;
    size_t available;
    size_t copy_length;

    header_length = log_prepare_header(msg->msg, sizeof(msg->msg) - 1, type, timestamp);
    if (header_length < 0 || header_length >= sizeof(msg->msg) - 1) {
        return -1;
    }

    available = (sizeof(msg->msg) - 2) - header_length;
    copy_length = body_size;
    if (copy_length > available) {
        copy_length = available;
    }

    memcpy(msg->msg + header_length, body, copy_length);
    msg->msg[header_length + copy_length] = '\n';
    msg->msg[header_length + copy_length + 1] = '\0';
    msg->size = header_length + copy_length + 1;

    return 0;
}

static struct flb_log_record *log_record_clone(int type,
                                               const struct flb_time *timestamp,
                                               const char *msg, size_t size)
{
    struct flb_log_record *record;

    record = flb_malloc(sizeof(struct flb_log_record) + size);
    if (record == NULL) {
        flb_errno();
        return NULL;
    }

    record->type = type;
    record->timestamp_sec = timestamp->tm.tv_sec;
    record->timestamp_nsec = timestamp->tm.tv_nsec;
    record->size = size;
    record->next = NULL;
    memcpy(record->msg, msg, size);

    return record;
}

void flb_log_record_destroy(struct flb_log_record *record)
{
    if (record != NULL) {
        flb_free(record);
    }
}

static struct flb_log_record *log_queue_pop(struct flb_log_queue *queue)
{
    struct flb_log_record *record;

    pthread_mutex_lock(&queue->mutex);
    record = queue->head;
    if (record != NULL) {
        queue->head = record->next;
        if (queue->head == NULL) {
            queue->tail = NULL;
            queue->signal_pending = FLB_FALSE;
        }
        queue->length--;
        record->next = NULL;
    }
    else {
        queue->signal_pending = FLB_FALSE;
    }
    pthread_mutex_unlock(&queue->mutex);

    return record;
}

static void log_queue_cleanup(struct flb_log_queue *queue)
{
    struct flb_log_record *record;

    while ((record = log_queue_pop(queue)) != NULL) {
        flb_log_record_destroy(record);
    }
}

static int log_pipeline_signal(struct flb_log *log)
{
    int ret;

    ret = flb_pipe_w(log->pipeline_ch[1], ".", 1);
    if (ret <= 0) {
        flb_pipe_error();
        return -1;
    }

    return 0;
}

static void log_pipeline_mirror(struct flb_log *log, struct flb_log_record *record)
{
    int signal_pending;
    struct flb_time timestamp;
    struct flb_log_record *copy;

    if (log->pipeline_enabled == FLB_FALSE) {
        return;
    }

    timestamp.tm.tv_sec = record->timestamp_sec;
    timestamp.tm.tv_nsec = record->timestamp_nsec;

    copy = log_record_clone(record->type, &timestamp, record->msg, record->size);
    if (copy == NULL) {
        return;
    }

    pthread_mutex_lock(&log->pipeline_queue.mutex);
    if (log->pipeline_queue.length >= log->pipeline_queue.limit) {
        pthread_mutex_unlock(&log->pipeline_queue.mutex);
        flb_log_record_destroy(copy);
        return;
    }

    if (log->pipeline_queue.tail == NULL) {
        log->pipeline_queue.head = copy;
        log->pipeline_queue.tail = copy;
    }
    else {
        log->pipeline_queue.tail->next = copy;
        log->pipeline_queue.tail = copy;
    }

    log->pipeline_queue.length++;
    signal_pending = log->pipeline_queue.signal_pending;
    if (signal_pending == FLB_FALSE) {
        log->pipeline_queue.signal_pending = FLB_TRUE;
    }
    pthread_mutex_unlock(&log->pipeline_queue.mutex);

    if (signal_pending == FLB_FALSE && log_pipeline_signal(log) != 0) {
        pthread_mutex_lock(&log->pipeline_queue.mutex);
        log->pipeline_queue.signal_pending = FLB_FALSE;
        pthread_mutex_unlock(&log->pipeline_queue.mutex);
    }
}

static inline int log_push_record(struct flb_log_record *record, struct flb_log *log)
{
    struct log_message msg;
    struct flb_time timestamp;

    timestamp.tm.tv_sec = record->timestamp_sec;
    timestamp.tm.tv_nsec = record->timestamp_nsec;

    if (log_render_message(&msg, record->type, &timestamp,
                           record->msg, record->size) != 0) {
        fprintf(stderr, "[log] could not render log record\n");
        return -1;
    }

    return log_push(&msg, log);
}

static int log_queue_enqueue(struct flb_log *log, int type,
                             const struct flb_time *timestamp,
                             const char *msg, size_t size)
{
    int signal_pending;
    struct flb_log_record *record;

    record = log_record_clone(type, timestamp, msg, size);
    if (record == NULL) {
        return -1;
    }

    pthread_mutex_lock(&log->queue_mutex);

    if (log->queue_length >= log->queue_limit) {
        log->dropped_records++;
        pthread_mutex_unlock(&log->queue_mutex);
        flb_free(record);
        log_queue_increment_counter(log->metrics->queue_drop_counter, 1);
        return -1;
    }

    if (log->queue_tail == NULL) {
        log->queue_head = record;
        log->queue_tail = record;
    }
    else {
        log->queue_tail->next = record;
        log->queue_tail = record;
    }

    log->queue_length++;
    signal_pending = log->queue_signal_pending;
    if (signal_pending == FLB_FALSE) {
        log->queue_signal_pending = FLB_TRUE;
    }
    pthread_mutex_unlock(&log->queue_mutex);

    if (signal_pending == FLB_FALSE) {
        if (flb_log_enqueue_signal(log, FLB_LOG_MNG_DRAIN_SIGNAL) != 0) {
            pthread_mutex_lock(&log->queue_mutex);
            log->queue_signal_pending = FLB_FALSE;
            pthread_mutex_unlock(&log->queue_mutex);
            return -1;
        }
    }

    log_queue_increment_counter(log->metrics->queue_enqueue_counter, 1);

    return 0;
}

static struct flb_log_record *log_queue_dequeue(struct flb_log *log)
{
    struct flb_log_record *record;

    pthread_mutex_lock(&log->queue_mutex);
    record = log->queue_head;

    if (record != NULL) {
        log->queue_head = record->next;
        if (log->queue_head == NULL) {
            log->queue_tail = NULL;
            log->queue_signal_pending = FLB_FALSE;
        }
        log->queue_length--;
        record->next = NULL;
    }
    else {
        log->queue_signal_pending = FLB_FALSE;
    }

    pthread_mutex_unlock(&log->queue_mutex);

    return record;
}

static void log_queue_destroy(struct flb_log *log)
{
    struct flb_log_record *record;

    while ((record = log_queue_dequeue(log)) != NULL) {
        flb_free(record);
    }
}

static void log_queue_report_drops(struct flb_log *log)
{
    int len;
    size_t dropped_records;
    struct log_message msg = {0};

    pthread_mutex_lock(&log->queue_mutex);
    dropped_records = log->dropped_records;
    log->dropped_records = 0;
    pthread_mutex_unlock(&log->queue_mutex);

    if (dropped_records == 0) {
        return;
    }

    len = snprintf(msg.msg,
                   sizeof(msg.msg),
                   "[log] dropped %zu log records due to logger queue saturation\n",
                   dropped_records);
    if (len <= 0) {
        return;
    }

    msg.size = (size_t) len;
    log_push(&msg, log);
}

/* Central collector of messages */
static void log_worker_collector(void *data)
{
    int run = FLB_TRUE;
    struct flb_log *log = data;
    struct mk_event *event = NULL;
    struct flb_log_record *record;
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
            if (event->type == FLB_LOG_MNG) {
                signal_value = flb_log_consume_signal(log);

                if (signal_value == FLB_LOG_MNG_TERMINATION_SIGNAL) {
                    run = FLB_FALSE;
                }
                else if (signal_value == FLB_LOG_MNG_DRAIN_SIGNAL ||
                         signal_value == FLB_LOG_MNG_REFRESH_SIGNAL) {
                    while ((record = log_queue_dequeue(log)) != NULL) {
                        log_queue_report_drops(log);
                        log_pipeline_mirror(log, record);
                        log_push_record(record, log);
                        log_queue_increment_counter(log->metrics->queue_drain_counter, 1);
                        flb_free(record);
                    }

                    log_queue_report_drops(log);
                }
            }
        }
    }

    while ((record = log_queue_dequeue(log)) != NULL) {
        log_queue_report_drops(log);
        log_pipeline_mirror(log, record);
        log_push_record(record, log);
        log_queue_increment_counter(log->metrics->queue_drain_counter, 1);
        flb_free(record);
    }
    log_queue_report_drops(log);

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
    (void) worker;
    return 0;
}

int flb_log_worker_init(struct flb_worker *worker)
{
    struct flb_log_cache *cache;

    /* Log cache to reduce noise */
    cache = flb_log_cache_create(10, FLB_LOG_CACHE_ENTRIES);
    if (!cache) {
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
        log_close_sink(log);
        log->type = FLB_LOG_FILE;
        log->out = out;
        if (log_open_sink(log) == -1) {
            log->type = FLB_LOG_STDERR;
            log->out = NULL;
        }
    }
    else {
        log_close_sink(log);
        log->type = FLB_LOG_STDERR;
        log->out = NULL;
    }

    return 0;
}

int flb_log_pipeline_enable(struct flb_config *config)
{
    int ret;
    struct flb_log *log;

    log = config->log;
    if (log == NULL) {
        return -1;
    }

    if (log->pipeline_enabled == FLB_TRUE) {
        return 0;
    }

    ret = flb_pipe_create(log->pipeline_ch);
    if (ret != 0) {
        return -1;
    }

    flb_pipe_set_nonblocking(log->pipeline_ch[0]);
    flb_pipe_set_nonblocking(log->pipeline_ch[1]);

    log->pipeline_enabled = FLB_TRUE;

    return 0;
}

void flb_log_pipeline_disable(struct flb_config *config)
{
    struct flb_log *log;

    if (config == NULL || config->log == NULL) {
        return;
    }

    log = config->log;
    if (log->pipeline_enabled == FLB_FALSE) {
        return;
    }

    log->pipeline_enabled = FLB_FALSE;
    log_queue_cleanup(&log->pipeline_queue);
    flb_pipe_destroy(log->pipeline_ch);
    log->pipeline_ch[0] = -1;
    log->pipeline_ch[1] = -1;
}

flb_pipefd_t flb_log_pipeline_get_event_fd(struct flb_config *config)
{
    if (config == NULL || config->log == NULL) {
        return -1;
    }

    return config->log->pipeline_ch[0];
}

struct flb_log_record *flb_log_pipeline_dequeue(struct flb_config *config)
{
    if (config == NULL || config->log == NULL) {
        return NULL;
    }

    return log_queue_pop(&config->log->pipeline_queue);
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

    metrics->queue_enqueue_counter = cmt_counter_create(metrics->cmt,
                                                        "fluentbit",
                                                        "logger",
                                                        "queue_enqueued_total",
                                                        "Total number of logger queue enqueues",
                                                        0, NULL);
    if (metrics->queue_enqueue_counter == NULL) {
        flb_log_metrics_destroy(metrics);
        return NULL;
    }

    metrics->queue_drop_counter = cmt_counter_create(metrics->cmt,
                                                     "fluentbit",
                                                     "logger",
                                                     "queue_dropped_total",
                                                     "Total number of logger queue drops",
                                                     0, NULL);
    if (metrics->queue_drop_counter == NULL) {
        flb_log_metrics_destroy(metrics);
        return NULL;
    }

    metrics->queue_drain_counter = cmt_counter_create(metrics->cmt,
                                                      "fluentbit",
                                                      "logger",
                                                      "queue_drained_total",
                                                      "Total number of logger queue records drained",
                                                      0, NULL);
    if (metrics->queue_drain_counter == NULL) {
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
    log->out_fd = -1;
    log->out   = out;
    log->evl   = evl;
    log->tid   = 0;
    log->queue_limit = FLB_LOG_QUEUE_LIMIT;
    pthread_mutex_init(&log->queue_mutex, NULL);
    log->pipeline_enabled = FLB_FALSE;
    log->pipeline_ch[0] = -1;
    log->pipeline_ch[1] = -1;
    log->pipeline_queue.limit = FLB_LOG_QUEUE_LIMIT;
    pthread_mutex_init(&log->pipeline_queue.mutex, NULL);

    if (log->type == FLB_LOG_FILE && log->out != NULL) {
        if (log_open_sink(log) == -1) {
            log->type = FLB_LOG_STDERR;
            log->out = NULL;
        }
    }

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

static int flb_log_construct(int type, const char *file, int line,
                             const char *fmt, va_list *args,
                             struct flb_time *timestamp,
                             char *body, size_t body_size,
                             int *ret_len)
{
    int ret;
    int header_length;

    (void) file;
    (void) line;

    flb_time_get(timestamp);
    header_length = log_prepare_header(body, body_size, type, timestamp);
    if (header_length < 0 || header_length >= body_size - 1) {
        return -1;
    }

    body_size = (body_size - 2) - header_length;
    ret = vsnprintf(body, body_size, fmt, *args);
    if (ret < 0) {
        return -1;
    }

    if (ret_len != NULL) {
        *ret_len = header_length;
    }

    if (ret >= body_size) {
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
    char body[sizeof(((struct log_message *) 0)->msg)];
    struct flb_time timestamp;
    va_list args;

    va_start(args, fmt);
    ret = flb_log_construct(type, file, line, fmt, &args,
                            &timestamp, body, sizeof(body), &len);
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
    char body[sizeof(((struct log_message *) 0)->msg)];
    struct log_message msg = {0};
    struct flb_time timestamp;
    va_list args;
    const char *msg_type_str;
    uint64_t ts;

    struct flb_worker *w;
    struct flb_config *config;

    va_start(args, fmt);
    ret = flb_log_construct(type, file, line, fmt, &args,
                            &timestamp, body, sizeof(body), &len);
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

            n = log_queue_enqueue(config->log, type, &timestamp,
                                  body, strlen(body));

            if (n == -1) {
                if (log_render_message(&msg, type, &timestamp,
                                       body, strlen(body)) == 0) {
                    fprintf(stderr, "%s", (char *) msg.msg);
                }
            }
        }
        else {
            if (log_render_message(&msg, type, &timestamp,
                                   body, strlen(body)) == 0) {
                fprintf(stderr, "%s", (char *) msg.msg);
            }
        }
    }
    else {
        if (log_render_message(&msg, type, &timestamp,
                               body, strlen(body)) == 0) {
            fprintf(stderr, "%s", (char *) msg.msg);
        }
    }

    #ifdef FLB_HAVE_AWS_ERROR_REPORTER
    if (is_error_reporting_enabled()) {
        if (type == FLB_LOG_ERROR) {
            flb_aws_error_reporter_write(error_reporter, body);
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
    log_close_sink(log);
    log_queue_destroy(log);
    pthread_mutex_destroy(&log->queue_mutex);
    flb_log_pipeline_disable(config);
    pthread_mutex_destroy(&log->pipeline_queue.mutex);
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
