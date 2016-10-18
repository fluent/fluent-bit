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

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_stats.h>
#include <fluent-bit/flb_kernel.h>

#include "proc.h"

#define IN_MEM_COLLECT_SEC  1
#define IN_MEM_COLLECT_NSEC 0

struct flb_in_mem_config {
    int    idx;
    int    page_size;
    pid_t  pid;
    msgpack_packer  pckr;
    msgpack_sbuffer sbuf;
};

struct flb_input_plugin in_mem_plugin;

static int in_mem_collect(struct flb_config *config, void *in_context);

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

    bytes = read(fd, buf, sizeof(buf) - 1);
    if (bytes == -1) {
        perror("read");
        close(fd);
        return -1;
    }
    close(fd);
    buf[bytes] = '\0';

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

static int in_mem_init(struct flb_input_instance *in,
                       struct flb_config *config, void *data)
{
    int ret;
    char *tmp;
    struct flb_in_mem_config *ctx;
    (void) data;

    /* Initialize context */
    ctx = malloc(sizeof(struct flb_in_mem_config));
    if (!ctx) {
        return -1;
    }
    ctx->idx = 0;
    ctx->pid = 0;
    ctx->page_size = sysconf(_SC_PAGESIZE);

    /* Check if the caller want's to trace a specific Process ID */
    tmp = flb_input_get_property("pid", in);
    if (tmp) {
        ctx->pid = atoi(tmp);
    }

    /* Init msgpack buffers */
    msgpack_sbuffer_init(&ctx->sbuf);
    msgpack_packer_init(&ctx->pckr, &ctx->sbuf, msgpack_sbuffer_write);

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set the collector */
    ret = flb_input_set_collector_time(in,
                                       in_mem_collect,
                                       IN_MEM_COLLECT_SEC,
                                       IN_MEM_COLLECT_NSEC,
                                       config);
    if (ret == -1) {
        flb_error("Could not set collector for memory input plugin");
    }

    return 0;
}

static int in_mem_collect(struct flb_config *config, void *in_context)
{
    int ret;
    int len;
    int entries = 2;
    uint64_t total;
    uint64_t free;
    struct proc_task *task = NULL;
    struct flb_in_mem_config *ctx = in_context;

    if (ctx->pid) {
        task = proc_stat(ctx->pid, ctx->page_size);
        if (!task) {
            flb_warn("[in_mem] could not measure PID %i", ctx->pid);
            ctx->pid = 0;
        }
    }

    if (config->kernel->n_version < FLB_KERNEL_VERSION(3, 14, 0)) {
        ret = mem_calc_old(&total, &free);
    }
    else {
        ret = mem_calc(&total, &free);
    }

    if (ret == -1) {
        if (task) {
            proc_free(task);
        }
        return -1;
    }

    if (task) {
        entries += 2;
    }

    msgpack_pack_array(&ctx->pckr, 2);
    msgpack_pack_uint64(&ctx->pckr, time(NULL));
    msgpack_pack_map(&ctx->pckr, entries);

    msgpack_pack_bin(&ctx->pckr, 5);
    msgpack_pack_bin_body(&ctx->pckr, "total", 5);
    msgpack_pack_uint32(&ctx->pckr, total);

    msgpack_pack_bin(&ctx->pckr, 4);
    msgpack_pack_bin_body(&ctx->pckr, "free", 4);
    msgpack_pack_uint32(&ctx->pckr, free);

    if (task) {
        /* RSS bytes */
        msgpack_pack_bin(&ctx->pckr, 10);
        msgpack_pack_bin_body(&ctx->pckr, "proc_bytes", 10);
        msgpack_pack_uint64(&ctx->pckr, task->proc_rss);

        /* RSS Human readable format */
        len = strlen(task->proc_rss_hr);
        msgpack_pack_bin(&ctx->pckr, 7);
        msgpack_pack_bin_body(&ctx->pckr, "proc_hr", 7);
        msgpack_pack_str(&ctx->pckr, len);
        msgpack_pack_str_body(&ctx->pckr, task->proc_rss_hr, len);

        proc_free(task);
    }

    flb_trace("[in_mem] memory total=%lu kb, available=%d kb",
              total, free);
    ++ctx->idx;

    flb_stats_update(in_mem_plugin.stats_fd, 0, 1);
    return 0;
}

static void *in_mem_flush(void *in_context, size_t *size)
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

static int in_mem_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_mem_config *ctx = data;

    /* Remove msgpack buffer */
    msgpack_sbuffer_destroy(&ctx->sbuf);

    /* done */
    free(ctx);

    return 0;
}

struct flb_input_plugin in_mem_plugin = {
    .name         = "mem",
    .description  = "Memory Usage",
    .cb_init      = in_mem_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_mem_collect,
    .cb_flush_buf = in_mem_flush,
    .cb_exit      = in_mem_exit
};
