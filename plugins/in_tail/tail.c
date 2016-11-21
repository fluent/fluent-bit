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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_stats.h>

#include "tail.h"
#include "tail_fs.h"
#include "tail_file.h"
#include "tail_config.h"

static inline int consume_byte(int fd)
{
    int ret;
    uint64_t val;

    /* We need to consume the byte */
    ret = read(fd, &val, sizeof(val));
    if (ret <= 0) {
        flb_errno();
        return -1;
    }

    return 0;
}

static inline int tail_signal_manager(struct flb_tail_config *ctx)
{
    int n;
    uint64_t val = 0xc001;

    /* Insert a dummy event into the channel manager */
    n = write(ctx->ch_manager[1], &val, sizeof(val));
    if (n == -1) {
        flb_errno();
        return -1;
    }

    return n;
}

/* cb_collect callback */
static int in_tail_collect_static(struct flb_config *config, void *in_context)
{
    int ret;
    int active = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file;

    /* Do a data chunk collection for each file */
    mk_list_foreach_safe(head, tmp, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        ret = flb_tail_file_chunk(file);
        switch (ret) {
        case FLB_TAIL_ERROR:
            /* Could not longer read the file */
            flb_tail_file_remove(file);
            break;
        case FLB_TAIL_OK:
            active++;
            continue;
        case FLB_TAIL_WAIT:
            /* Promote file to 'events' type handler */
            flb_debug("[in_tail] file=%s promote to TAIL_EVENT", file->name);
            flb_tail_file_to_event(file);
            break;
        }
    }

    /*
     * If there are no more active static handlers, we consume the 'byte' that
     * triggered this event so this is not longer called again.
     */
    if (active == 0) {
        consume_byte(ctx->ch_manager[0]);
    }

    return 0;
}


int in_tail_collect_event(void *file, struct flb_config *config)
{
    int ret;
    struct flb_tail_file *f = file;

    flb_debug("[in_tail] file=%s event", f->name);

    ret = flb_tail_file_chunk(f);
    switch (ret) {
    case FLB_TAIL_ERROR:
        /* Could not longer read the file */
        flb_tail_file_remove(f);
        break;
    case FLB_TAIL_OK:
    case FLB_TAIL_WAIT:
        break;
    }

    return 0;
}


/* Initialize plugin */
static int in_tail_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_tail_config *ctx = NULL;

    /* Allocate space for the configuration */
    ctx = flb_tail_config_create(in);
    if (!ctx) {
        return -1;
    }

    flb_trace("[in_tail] path: %s", ctx->path);
    flb_input_set_context(in, ctx);

    ret = flb_input_set_collector_event(in, in_tail_collect_static,
                                        ctx->ch_manager[0], config);
    if (ret != 0) {
        flb_tail_config_destroy(ctx);
        return -1;
    }

    /* Initialize file-system watcher */
    ret = flb_tail_fs_init(in, ctx, config);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

/* Pre-run callback / before the event loop */
static int in_tail_pre_run(void *in_context, struct flb_config *config)
{
    struct flb_tail_config *ctx = in_context;

    return tail_signal_manager(ctx);
}

/* cb_flush callback */
static void *in_tail_flush(void *in_context, size_t *size)
{
    char *buf = NULL;
    struct flb_tail_config *ctx = in_context;

    if (ctx->mp_sbuf.size == 0) {
        *size = 0;
        return NULL;
    }

    buf = flb_malloc(ctx->mp_sbuf.size);
    if (!buf) {
        return NULL;
    }

    memcpy(buf, ctx->mp_sbuf.data, ctx->mp_sbuf.size);
    *size = ctx->mp_sbuf.size;

    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck,
                        &ctx->mp_sbuf, msgpack_sbuffer_write);

    return buf;
}

static int in_tail_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_tail_config *ctx = data;

    flb_tail_file_remove_all(ctx);
    flb_free(ctx);

    return 0;
}


struct flb_input_plugin in_tail_plugin = {
    .name         = "tail",
    .description  = "Tail files",
    .cb_init      = in_tail_init,
    .cb_pre_run   = in_tail_pre_run,
    .cb_collect   = NULL,
    .cb_flush_buf = in_tail_flush,
    .cb_exit      = in_tail_exit
};
