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
#include <unistd.h>
#include <assert.h>

#include <msgpack.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>

#include "fluentd.h"

struct flb_output_plugin out_fluentd_plugin;

int cb_fluentd_init(struct flb_config *config)
{
    int ret;
    struct flb_out_fluentd_config *ctx;

    ctx = calloc(1, sizeof(struct flb_out_fluentd_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }

    ret = flb_output_set_context("fluentd", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for fluentd output plugin");
    }

    return 0;
}

int cb_fluentd_flush(void *data, size_t bytes, void *out_context,
                     struct flb_config *config)
{
    int fd;
    int ret = -1;
    int maps = 0;
    size_t total;
    size_t bytes_sent;
    char *buf = NULL;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    msgpack_unpacked mp_umsg;
    size_t mp_upos = 0;
    (void) out_context;
    (void) config;

    /*
     * The incoming data comes in Fluent Bit format an array of objects, as we
     * aim to send this information to Fluentd through it in_forward plugin, we
     * need to transform the data. The Fluentd in_forward plugin allows one
     * of the following formats:
     *
     *   1. [tag, time, record]
     *
     *    or
     *
     *   2. [tag, [[time,record], [time,record], ...]]
     *
     *   we use the format #2
     */

    /* Initialize packager */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Count the number of map entries
     *
     * FIXME: Fluent Bit should expose the number of maps into the
     * data, so we avoid this silly counting.
     */
    msgpack_unpacked_init(&mp_umsg);
    while (msgpack_unpack_next(&mp_umsg, data, bytes, &mp_upos)) {
        maps++;
    }
    msgpack_unpacked_destroy(&mp_umsg);

    /* Output: root array */
    msgpack_pack_array(&mp_pck, 2);
    msgpack_pack_bin(&mp_pck, sizeof(FLB_CONFIG_DEFAULT_TAG) - 1);
    msgpack_pack_bin_body(&mp_pck,
                          FLB_CONFIG_DEFAULT_TAG,
                          sizeof(FLB_CONFIG_DEFAULT_TAG) - 1);
    msgpack_pack_array(&mp_pck, maps);

    /* Allocate a new buffer to merge data */
    total = bytes + mp_sbuf.size;
    buf = malloc(total);
    if (!buf) {
        perror("malloc");
        return -1;
    }

    memcpy(buf, mp_sbuf.data, mp_sbuf.size);
    memcpy(buf + mp_sbuf.size, data, bytes);
    msgpack_sbuffer_destroy(&mp_sbuf);

    ret = flb_io_write(&out_fluentd_plugin, buf, total, &bytes_sent);
    free(buf);

    return ret;
}

/* Plugin reference */
struct flb_output_plugin out_fluentd_plugin = {
    .name         = "fluentd",
    .description  = "Fluentd log collector",
    .cb_init      = cb_fluentd_init,
    .cb_pre_run   = NULL,
    .cb_flush     = cb_fluentd_flush,
    .flags        = FLB_OUTPUT_TCP,
};
