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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <inttypes.h>
#include <time.h>

#include "in_kmsg.h"

/*
 * Note: Functions timeval_diff() and in_kmsg_boot_time() are based
 * on syslog-ng-3.5 source code.
 */
static inline uint64_t timeval_diff(struct timeval *t1, struct timeval *t2)
{
    return ((uint64_t) t1->tv_sec - (uint64_t) t2->tv_sec) * KMSG_USEC_PER_SEC +
        ((uint64_t) t1->tv_usec - (uint64_t) t2->tv_usec);
}

static int boot_time(struct timeval *boot_time)
{
    int fd, pos = 0;
    int bytes;
    uint64_t tdiff;
    char buf[256];
    struct timeval curr_time;

    fd = open("/proc/uptime", O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    bytes = read(fd, buf, sizeof(buf));
    if (bytes <= 0) {
        close(fd);
        return -1;
    }

    close(fd);
    gettimeofday(&curr_time, NULL);

    /* Read the seconds part */
    while (pos < bytes && buf[pos] != '.') {
        if (isdigit(buf[pos])) {
            boot_time->tv_sec = boot_time->tv_sec * 10 + ((buf[pos]) - '0');
        }
        else {
            boot_time->tv_sec = 0;
            return 0;
        }
        pos++;
    }
    pos++;

    /* Then the microsecond part */
    while (pos < bytes && buf[pos] != ' ') {
        if (isdigit(buf[pos])) {
            boot_time->tv_usec = boot_time->tv_usec * 10 + ((buf[pos]) - '0');
        }
        else {
            boot_time->tv_sec = 0;
            boot_time->tv_usec = 0;
            return 0;
        }
        pos++;
    }

    tdiff = timeval_diff(&curr_time, boot_time);
    boot_time->tv_sec  = tdiff / KMSG_USEC_PER_SEC;
    boot_time->tv_usec = tdiff % KMSG_USEC_PER_SEC;

    return 0;
}

static inline int process_line(const char *line,
                               struct flb_input_instance *i_ins,
                               struct flb_in_kmsg_config *ctx)
{
    char priority;           /* log priority                */
    uint64_t sequence;       /* sequence number             */
    struct timeval tv;       /* time value                  */
    int line_len;
    uint64_t val;
    long pri_val;
    const char *p = line;
    char *end = NULL;
    struct flb_time ts;
    int ret;

    /* Increase buffer position */
    ctx->buffer_id++;

    errno = 0;
    pri_val = strtol(p, &end, 10);
    if ((errno == ERANGE && (pri_val == INT_MAX || pri_val == INT_MIN))
        || (errno != 0 && pri_val == 0)) {
        goto fail;
    }

    /* Priority */
    priority = FLB_KLOG_PRI(pri_val);

    if (priority > ctx->prio_level) {
        /* Drop line */
        return 0;
    }

    /* Sequence */
    p = strchr(p, ',');
    if (!p) {
        goto fail;
    }
    p++;

    errno = 0;
    val = strtoull(p, &end, 10);
    if ((errno == ERANGE && val == ULLONG_MAX)
        || (errno != 0 && val == 0)) {
        goto fail;
    }

    sequence = val;
    p = ++end;

    /* Timestamp */
    val = strtoull(p, &end, 10);
    if ((errno == ERANGE && val == ULLONG_MAX)
        || (errno != 0 && val == 0)) {
        goto fail;
    }

    tv.tv_sec  = val/1000000;
    tv.tv_usec = val - (tv.tv_sec * 1000000);

    flb_time_set(&ts, ctx->boot_time.tv_sec + tv.tv_sec, tv.tv_usec * 1000);

    /* Now process the human readable message */
    p = strchr(p, ';');
    if (!p) {
        goto fail;
    }
    p++;

    line_len = strlen(p);

    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_timestamp(
                &ctx->log_encoder,
                &ts);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
                &ctx->log_encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("priority"),
                FLB_LOG_EVENT_CHAR_VALUE(priority),

                FLB_LOG_EVENT_CSTRING_VALUE("sequence"),
                FLB_LOG_EVENT_UINT64_VALUE(sequence),

                FLB_LOG_EVENT_CSTRING_VALUE("sec"),
                FLB_LOG_EVENT_UINT64_VALUE(tv.tv_sec),

                FLB_LOG_EVENT_CSTRING_VALUE("usec"),
                FLB_LOG_EVENT_UINT64_VALUE(tv.tv_usec),

                FLB_LOG_EVENT_CSTRING_VALUE("msg"),
                FLB_LOG_EVENT_STRING_VALUE((char *) p, line_len - 1));
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(ctx->ins, NULL, 0,
                             ctx->log_encoder.output_buffer,
                             ctx->log_encoder.output_length);

        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "Error encoding record : %d", ret);

        ret = -1;
    }

    flb_log_event_encoder_reset(&ctx->log_encoder);

    flb_plg_debug(ctx->ins, "pri=%i seq=%" PRIu64 " sec=%ld usec=%ld msg_length=%i",
                  priority,
                  sequence,
                  (long int) tv.tv_sec,
                  (long int) tv.tv_usec,
                  line_len - 1);
    return ret;

 fail:
    ctx->buffer_id--;
    return -1;
}

/* Callback triggered when some Kernel Log buffer msgs are available */
static int in_kmsg_collect(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *in_context)
{
    int ret;
    int bytes;
    struct flb_in_kmsg_config *ctx = in_context;

    bytes = read(ctx->fd, ctx->buf_data, ctx->buf_size - 1);
    if (bytes == -1) {
        if (errno == -EPIPE) {
            return -1;
        }
        return 0;
    }
    else if (bytes == 0) {
        flb_errno();
        return 0;
    }
    ctx->buf_len += bytes;

    /* Always set a delimiter to avoid buffer trash */
    ctx->buf_data[ctx->buf_len] = '\0';

    /* Check if our buffer is full */
    if (ctx->buffer_id + 1 == KMSG_BUFFER_SIZE) {
        ret = flb_engine_flush(config, &in_kmsg_plugin);
        if (ret == -1) {
            ctx->buffer_id = 0;
        }
    }

    /* Process and enqueue the received line */
    process_line(ctx->buf_data, i_ins, ctx);
    ctx->buf_len = 0;

    return 0;
}

/* Init kmsg input */
static int in_kmsg_init(struct flb_input_instance *ins,
                        struct flb_config *config, void *data)
{
    int fd;
    int ret;
    struct flb_in_kmsg_config *ctx;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_in_kmsg_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->buf_data = flb_malloc(FLB_KMSG_BUF_SIZE);
    if (!ctx->buf_data) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }
    ctx->buf_len = 0;
    ctx->buf_size = FLB_KMSG_BUF_SIZE;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* set context */
    flb_input_set_context(ins, ctx);

    /* open device */
    fd = open(FLB_KMSG_DEV, O_RDONLY);
    if (fd == -1) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }
    ctx->fd = fd;

    /* get the system boot time */
    ret = boot_time(&ctx->boot_time);
    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not get system boot time for kmsg input plugin");
        flb_free(ctx);
        return -1;
    }
    flb_plg_debug(ctx->ins, "prio_level is %d", ctx->prio_level);

    /* Set our collector based on a file descriptor event */
    ret = flb_input_set_collector_event(ins,
                                        in_kmsg_collect,
                                        ctx->fd,
                                        config);
    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not set collector for kmsg input plugin");
        flb_free(ctx);
        return -1;
    }

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);

        flb_free(ctx);

        return -1;
    }

    return 0;
}

static int in_kmsg_exit(void *data, struct flb_config *config)
{
    (void)*config;
    struct flb_in_kmsg_config *ctx = data;

    flb_log_event_encoder_destroy(&ctx->log_encoder);

    if (ctx->fd >= 0) {
        close(ctx->fd);
    }

    flb_free(ctx->buf_data);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_INT, "prio_level", "8",
      0, FLB_TRUE, offsetof(struct flb_in_kmsg_config, prio_level),
      "The log level to filter. The kernel log is dropped if its priority is more than prio_level. "
      "Allowed values are 0-8. Default is 8."
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_kmsg_plugin = {
    .name         = "kmsg",
    .description  = "Kernel Log Buffer",
    .cb_init      = in_kmsg_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_kmsg_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_kmsg_exit,
    .config_map   = config_map
};
