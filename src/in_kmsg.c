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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <fluent-bit/in_kmsg.h>
#include <fluent-bit/flb_input.h>

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
            line[bytes - 1] = '\0';
            printf("%s\n", line);
        }
    }

    return 0;
}

/* Callback triggered when some Kernel Ring buffer msgs are available */
int in_kmsg_collect(void *in_context)
{
    int bytes;
    char line[1024];
    struct flb_in_kmsg_config *ctx = in_context;

    bytes = read(ctx->fd, line, sizeof(line) -1);
    if (bytes == -1) {
        if (errno == -EPIPE) {
            return -1;
        }
    }
    else if (bytes > 0) {
        /* Always set a delimiter to avoid buffer trash */
        line[bytes - 1] = '\0';
        printf("%s\n", line);
    }
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
        flb_utils_error_c("Could not open kernel ring buffer on kmsg plugin");
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
}


/* Plugin reference */
struct flb_input_plugin in_kmsg_plugin = {
    .name       = "kmsg",
    .cb_init    = in_kmsg_init,
    .cb_pre_run = NULL,
    .cb_collect = in_kmsg_collect,
    .cb_flush   = NULL
};
