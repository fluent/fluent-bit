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
#include <sys/sysinfo.h>
#include <fluent-bit/flb_stats.h>

#include "in_mem.h"
struct flb_input_plugin in_mem_plugin;

int in_mem_collect(struct flb_config *config, void *in_context);

int in_mem_init(struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_mem_config *ctx;
    (void) data;

    ctx = malloc(sizeof(struct flb_in_mem_config));
    if (!ctx) {
        return -1;
    }
    ctx->idx = 0;
    msgpack_sbuffer_init(&ctx->sbuf);
    msgpack_packer_init(&ctx->pckr, &ctx->sbuf, msgpack_sbuffer_write);
    ret = flb_input_set_context("mem", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for "
                          "memory input plugin");
    }
    ret = flb_input_set_collector_time("mem",
                                       in_mem_collect,
                                       IN_MEM_COLLECT_SEC,
                                       IN_MEM_COLLECT_NSEC,
                                       config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for memory input plugin");
    }
    return 0;
}

int in_mem_collect(struct flb_config *config, void *in_context)
{
    struct sysinfo info;
    (void) config;
    struct flb_in_mem_config *ctx = in_context;
    uint32_t totalram, freeram;

    sysinfo(&info);
    totalram = info.totalram / 1024;
    freeram  = info.freeram  / 1024;

    msgpack_pack_array(&ctx->pckr, 2);
    msgpack_pack_uint64(&ctx->pckr, time(NULL));
    msgpack_pack_map(&ctx->pckr, 2);
    msgpack_pack_bin(&ctx->pckr, 5);
    msgpack_pack_bin_body(&ctx->pckr, "total", 5);
    msgpack_pack_uint32(&ctx->pckr, totalram);
    msgpack_pack_bin(&ctx->pckr, 4);
    msgpack_pack_bin_body(&ctx->pckr, "free", 4);
    msgpack_pack_uint32(&ctx->pckr, freeram);

    flb_debug("[in_mem] memory total %lu kb, free %d kb (buffer=%i)",
              info.totalram/1024,
              info.freeram/1024,
              ctx->idx);
    ++ctx->idx;

    flb_stats_update(in_mem_plugin.stats_fd, 0, 1);
    return 0;
}

void *in_mem_flush(void *in_context, int *size)
{
    char *buf;
    struct flb_in_mem_config *ctx = in_context;

    if (ctx->idx == 0)
        return NULL;

    buf = malloc(ctx->sbuf.size);
    if (!buf) {
        return NULL;
    }
    memcpy(buf, ctx->sbuf.data, ctx->sbuf.size);
    *size = ctx->sbuf.size;
    msgpack_sbuffer_destroy(&ctx->sbuf);
    msgpack_sbuffer_init(&ctx->sbuf);
    msgpack_packer_init(&ctx->pckr, &ctx->sbuf, msgpack_sbuffer_write);
    ctx->idx = 0;
    return buf;
}

struct flb_input_plugin in_mem_plugin = {
    .name         = "mem",
    .description  = "Memory Usage",
    .cb_init      = in_mem_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_mem_collect,
    .cb_flush_buf = in_mem_flush
};
