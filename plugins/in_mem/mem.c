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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fluent-bit/flb_stats.h>
#include <fluent-bit/flb_kernel.h>

#include "mem.h"

struct flb_input_plugin in_mem_plugin;

int in_mem_collect(struct flb_config *config, void *in_context);


/* Locate a specific key into the buffer */
static char *field(char *data, char *field)
{
    char *p;
    char *q;
    char *sep;
    char *value;
    int len = strlen(field);

    p = strstr(data, field);
    if (!p) {
        return NULL;
    }

    sep = strchr(p, ':');
    p = ++sep;
    p++;

    while (*p == ' ') p++;

    q = strchr(p, ' ');
    len = q - p;
    value = malloc(len + 1);
    strncpy(value, p, len);
    value[len] = '\0';

    return value;
}

static int mem_calc_old(uint64_t *total, uint64_t *available)
{
    int ret;
    struct sysinfo info;

    ret = sysinfo(&info);
    if (ret == -1) {
        perror("sysinfo");
        return -1;
    }

    /* set values in KBs */
    *total     = info.totalram / 1024;
    *available = info.freeram  / 1024;

    return 0;
}

static int mem_calc(uint64_t *total, uint64_t *available)
{
    int fd;
    int bytes;
    char buf[1024];
    char *tmp;

    fd = open("/proc/meminfo", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return -1;
    }

    bytes = read(fd, buf, sizeof(buf));
    if (bytes == -1) {
        perror("read");
        close(fd);
        return -1;
    }
    close(fd);

    /* Total Memory */
    tmp = field(buf, "MemTotal");
    if (!tmp) {
        return -1;
    }
    *total = atoll(tmp);
    free(tmp);

    /* Available Memory */
    tmp = field(buf, "MemAvailable");
    if (!tmp) {
        return -1;
    }
    *available = atoll(tmp);
    free(tmp);

    return 0;
}

int in_mem_init(struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_mem_config *ctx;
    (void) data;

    /* Initialize context */
    ctx = malloc(sizeof(struct flb_in_mem_config));
    if (!ctx) {
        return -1;
    }
    ctx->idx = 0;

    /* Init msgpack buffers */
    msgpack_sbuffer_init(&ctx->sbuf);
    msgpack_packer_init(&ctx->pckr, &ctx->sbuf, msgpack_sbuffer_write);

    /* Set the context */
    ret = flb_input_set_context("mem", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("could not set context for mem plugin");
    }

    /* Set the collector */
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
    int ret;
    uint64_t total;
    uint64_t free;
    struct flb_in_mem_config *ctx = in_context;

    if (config->kernel->n_version < FLB_KERNEL_VERSION(3, 14, 0)) {
        ret = mem_calc_old(&total, &free);
    }
    else {
        ret = mem_calc(&total, &free);
    }

    if (ret == -1) {
        return -1;
    }

    msgpack_pack_array(&ctx->pckr, 2);
    msgpack_pack_uint64(&ctx->pckr, time(NULL));
    msgpack_pack_map(&ctx->pckr, 2);

    msgpack_pack_bin(&ctx->pckr, 5);
    msgpack_pack_bin_body(&ctx->pckr, "total", 5);
    msgpack_pack_uint32(&ctx->pckr, total);

    msgpack_pack_bin(&ctx->pckr, 4);
    msgpack_pack_bin_body(&ctx->pckr, "free", 4);
    msgpack_pack_uint32(&ctx->pckr, free);

    flb_debug("[in_mem] memory total=%lu kb, available=%d",
              total, free);
    ++ctx->idx;

    flb_stats_update(in_mem_plugin.stats_fd, 0, 1);
    return 0;
}

void *in_mem_flush(void *in_context, int *size)
{
    char *buf;
    struct flb_in_mem_config *ctx = in_context;

    if (ctx->idx == 0) {
        return NULL;
    }

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
