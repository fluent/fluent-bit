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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
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

#include "in_kmsg.h"

struct flb_input_plugin in_kmsg_plugin;

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

static inline int process_line(char *line,
                               struct flb_input_instance *i_ins,
                               struct flb_in_kmsg_config *ctx)
{
    char priority;           /* log priority                */
    uint64_t sequence;       /* sequence number             */
    struct timeval tv;       /* time value                  */
    int line_len;
    uint64_t val;
    char *p = line;
    char *end = NULL;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_time ts;

    /* Increase buffer position */
    ctx->buffer_id++;

    errno = 0;
    val = strtol(p, &end, 10);
    if ((errno == ERANGE && (val == INT_MAX || val == INT_MIN))
        || (errno != 0 && val == 0)) {
        goto fail;
    }

    /* Priority */
    priority = FLB_KLOG_PRI(val);

    /* Sequence */
    p = strchr(p, ',');
    if (!p) {
        goto fail;
    }
    p++;

    val = strtol(p, &end, 10);
    if ((errno == ERANGE && (val == INT_MAX || val == INT_MIN))
        || (errno != 0 && val == 0)) {
        goto fail;
    }

    sequence = val;
    p = ++end;

    /* Timestamp */
    val = strtol(p, &end, 10);
    if ((errno == ERANGE && (val == INT_MAX || val == INT_MIN))
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

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Store the new data into the MessagePack buffer,
     * we handle this as a list of maps.
     */
    msgpack_pack_array(&mp_pck, 2);
    flb_time_append_to_msgpack(&ts, &mp_pck, 0);

    msgpack_pack_map(&mp_pck, 5);
    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "priority", 8);
    msgpack_pack_char(&mp_pck, priority);

    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "sequence", 8);
    msgpack_pack_uint64(&mp_pck, sequence);

    msgpack_pack_str(&mp_pck, 3);
    msgpack_pack_str_body(&mp_pck, "sec", 3);
    msgpack_pack_uint64(&mp_pck, tv.tv_sec);

    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "usec", 4);
    msgpack_pack_uint64(&mp_pck, tv.tv_usec);

    msgpack_pack_str(&mp_pck, 3);
    msgpack_pack_str_body(&mp_pck, "msg", 3);
    msgpack_pack_str(&mp_pck, line_len - 1);
    msgpack_pack_str_body(&mp_pck, p, line_len - 1);

    flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    flb_trace("[in_kmsg] pri=%i seq=%" PRIu64 " ts=%ld sec=%ld usec=%ld '%s'",
              priority,
              sequence,
              ts,
              (long int) tv.tv_sec,
              (long int) tv.tv_usec,
              (const char *) p);

    return 0;

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
int in_kmsg_init(struct flb_input_instance *in,
                 struct flb_config *config, void *data)
{
    int fd;
    int ret;
    struct flb_in_kmsg_config *ctx;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_in_kmsg_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }

    ctx->buf_data = flb_malloc(FLB_KMSG_BUF_SIZE);
    if (!ctx->buf_data) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }
    ctx->buf_len = 0;
    ctx->buf_size = FLB_KMSG_BUF_SIZE;

    /* set context */
    flb_input_set_context(in, ctx);

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
        flb_error("Could not get system boot time for kmsg input plugin");
        flb_free(ctx);
        return -1;
    }

    /* Set our collector based on a file descriptor event */
    ret = flb_input_set_collector_event(in,
                                        in_kmsg_collect,
                                        ctx->fd,
                                        config);
    if (ret == -1) {
        flb_error("Could not set collector for kmsg input plugin");
        flb_free(ctx);
        return -1;
    }

    return 0;
}

static int in_kmsg_exit(void *data, struct flb_config *config)
{
    (void)*config;
    struct flb_in_kmsg_config *ctx = data;

    if (ctx->fd >= 0) {
        close(ctx->fd);
    }

    flb_free(ctx->buf_data);
    flb_free(ctx);
    return 0;
}


/* Plugin reference */
struct flb_input_plugin in_kmsg_plugin = {
    .name         = "kmsg",
    .description  = "Kernel Log Buffer",
    .cb_init      = in_kmsg_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_kmsg_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_kmsg_exit
};
