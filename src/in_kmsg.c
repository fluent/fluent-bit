/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <fluent-bit/in_kmsg.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>

int in_kmsg_start()
{
    int fd;
    int bytes;
    char line[1024];

    fd = open(FLB_KMSG_DEV, O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    while (1) {
        bytes = read(fd, line, sizeof(line) - 1);

        if (bytes == -1) {
            if (errno == -EPIPE) {
                /* Message overwritten / circular buffer */
                continue;
            }
            break;
        }
        else if (bytes > 0) {
            /* Always set a delimiter to avoid buffer trash */

            printf("%s\n", line);
        }
    }

    return 0;
}

static inline int process_line(char *line, struct flb_in_kmsg_config *ctx)
{
    uint64_t val;
    char *p = line;
    char *end = NULL;
    struct kmsg_line *buf;

    /* Increase buffer position */
    ctx->buffer_id++;

    if (ctx->buffer_id == KMSG_BUFFER_SIZE) {
        /* fixme: FLUSH RIGHT AWAY */
        ctx->buffer_id = 0;
    }

    errno = 0;
    val = strtol(p, &end, 10);
    if ((errno == ERANGE && (val == INT_MAX || val == INT_MIN))
        || (errno != 0 && val == 0)) {
        goto fail;
    }

    /* Lookup */
    buf = &ctx->buffer[ctx->buffer_id];

    /* Priority */
    buf->priority = FLB_LOG_PRI(val);

    /* Sequence */
    p = strchr(p, ',');
    p++;

    val = strtol(p, &end, 10);
    if ((errno == ERANGE && (val == INT_MAX || val == INT_MIN))
        || (errno != 0 && val == 0)) {
        goto fail;
    }

    buf->sequence = val;
    p = ++end;

    /* Timestamp */
    val = strtol(p, &end, 10);
    if ((errno == ERANGE && (val == INT_MAX || val == INT_MIN))
        || (errno != 0 && val == 0)) {
        goto fail;
    }
    buf->tv.tv_sec = val;

    if (*end == '.') {
        p = ++end;
        val = strtol(p, &end, 10);
        if ((errno == ERANGE && (val == INT_MAX || val == INT_MIN))
            || (errno != 0 && val == 0)) {
            goto fail;
        }
        buf->tv.tv_usec = val;
    }
    else {
        buf->tv.tv_usec = 0;
    }

    /* Now process the human readable message */
    p = strchr(p, ';');
    if (!p) {
        goto fail;
    }
    p++;

    flb_debug("pri=%i seq=%lu sec=%lu usec=%lu '%s'",
              buf->priority, buf->sequence, buf->tv.tv_sec, buf->tv.tv_usec, p);
    return 0;


 fail:
    ctx->buffer_id--;
    return -1;
}

/* Callback triggered when some Kernel Log buffer msgs are available */
int in_kmsg_collect(void *in_context)
{
    int bytes;
    char line[2024];
    struct flb_in_kmsg_config *ctx = in_context;

    bytes = read(ctx->fd, line, sizeof(line) -1);
    if (bytes == -1) {
        if (errno == -EPIPE) {
            return -1;
        }
        return 0;
    }
    /* Always set a delimiter to avoid buffer trash */
    line[bytes - 1] = '\0';

    /* Process and enqueue the received line */
    process_line(line, ctx);
    return 0;
}

/* Init kmsg input */
int in_kmsg_init(struct flb_config *config)
{
    int fd;
    int ret;
    struct flb_in_kmsg_config *ctx;

    ctx = malloc(sizeof(struct flb_in_kmsg_config));
    if (!ctx) {
        return -1;
    }

    fd = open(FLB_KMSG_DEV, O_RDONLY);
    if (fd == -1) {
        perror("open");
        flb_utils_error_c("Could not open kernel log buffer on kmsg plugin");
    }

    ctx->fd = fd;
    ret = flb_input_set_context("kmsg", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for kmsg input plugin");
    }

    /* Set our collector based on time, CPU usage every 1 second */
    ret = flb_input_set_collector_event("kmsg",
                                        in_kmsg_collect,
                                        ctx->fd,
                                        config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for kmsg input plugin");
    }

    return 0;
}


/* Plugin reference */
struct flb_input_plugin in_kmsg_plugin = {
    .name       = "kmsg",
    .cb_init    = in_kmsg_init,
    .cb_pre_run = NULL,
    .cb_collect = in_kmsg_collect,
    .cb_flush   = NULL
};
