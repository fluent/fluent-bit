/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include "tail.h"
#include "tail_fs.h"
#include "tail_db.h"
#include "tail_file.h"
#include "tail_scan.h"
#include "tail_signal.h"
#include "tail_config.h"
#include "tail_multiline.h"

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

/* cb_collect callback */
static int in_tail_collect_pending(struct flb_input_instance *i_ins,
                                   struct flb_config *config, void *in_context)
{
    int ret;
    int active = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file;
    struct stat st;

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        if (file->pending_bytes <= 0) {
            continue;
        }

        /* Gather current file size */
        ret = fstat(file->fd, &st);
        if (ret == -1) {
            flb_errno();
            flb_tail_file_remove(file);
            continue;
        }

        ret = flb_tail_file_chunk(file);
        switch (ret) {
        case FLB_TAIL_ERROR:
            /* Could not longer read the file */
            flb_tail_file_remove(file);
            break;
        case FLB_TAIL_OK:
        case FLB_TAIL_BUSY:
            /*
             * Adjust counter to verify if we need a further read(2) later.
             * For more details refer to tail_fs_inotify.c:96.
             */
            if (file->offset < st.st_size) {
                file->pending_bytes = (st.st_size - file->offset);
                active++;
            }
            else {
                file->pending_bytes = 0;
            }
            break;
        }
    }

    /* If no more active files, consume pending signal so we don't get called again. */
    if (active == 0) {
        tail_consume_pending(ctx);
    }

    return 0;
}

/* cb_collect callback */
static int in_tail_collect_static(struct flb_input_instance *i_ins,
                                  struct flb_config *config, void *in_context)
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
        case FLB_TAIL_BUSY:
            active++;
            continue;
        case FLB_TAIL_WAIT:
            /* Promote file to 'events' type handler */
            flb_debug("[in_tail] file=%s promote to TAIL_EVENT", file->name);
            ret = flb_tail_file_to_event(file);
            if (ret == -1) {
                flb_debug("[in_tail] file=%s cannot promote, unregistering",
                          file->name);
                flb_tail_file_remove(file);
            }
            if (file->config->exit_on_eof) {
                flb_info("[in_tail] file=%s ended, stop", file->name);
                flb_engine_shutdown(config);
                exit(0);
            }
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
    ctx = flb_tail_config_create(in, config);
    if (!ctx) {
        return -1;
    }
    ctx->i_ins = in;

    /* Initialize file-system watcher */
    ret = flb_tail_fs_init(in, ctx, config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }

    /* Scan path */
    flb_tail_scan(ctx->path, ctx);
    flb_trace("[in_tail] path: %s", ctx->path);

    /* Set plugin context */
    flb_input_set_context(in, ctx);

    /* Register an event collector */
    ret = flb_input_set_collector_event(in, in_tail_collect_static,
                                        ctx->ch_manager[0], config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_static = ret;

    /* Register re-scan */
    ret = flb_input_set_collector_time(in, flb_tail_scan_callback,
                                       ctx->refresh_interval_sec,
                                       ctx->refresh_interval_nsec,
                                       config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_scan = ret;

    /* Register callback to purge rotated files */
    ret = flb_input_set_collector_time(in, flb_tail_file_rotated_purge,
                                       ctx->rotate_wait, 0,
                                       config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_rotated = ret;

    /* Register callback to process pending bytes in promoted files */
    ret = flb_input_set_collector_event(in, in_tail_collect_pending,
                                        ctx->ch_pending[0], config);//1, 0, config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_pending = ret;


    if (ctx->multiline == FLB_TRUE && ctx->parser) {
        ctx->parser = NULL;
        flb_warn("[in_tail] on multiline mode 'Parser' is not allowed "
                 "(parser disabled)");
    }

    /* Register callback to process multiline queued buffer */
    if (ctx->multiline == FLB_TRUE) {
        ret = flb_input_set_collector_time(in, flb_tail_mult_pending_flush,
                                           ctx->multiline_flush, 0,
                                           config);
        if (ret == -1) {
            ctx->multiline = FLB_FALSE;
            flb_tail_config_destroy(ctx);
            return -1;
        }
        ctx->coll_fd_mult_flush = ret;
    }

    return 0;
}

/* Pre-run callback / before the event loop */
static int in_tail_pre_run(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_tail_config *ctx = in_context;
    (void) i_ins;

    return tail_signal_manager(ctx);
}

static int in_tail_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_tail_config *ctx = data;

    if (ctx->exclude_list) {
        flb_utils_split_free(ctx->exclude_list);
    }

    flb_tail_file_remove_all(ctx);
    flb_tail_config_destroy(ctx);

    return 0;
}

static void in_tail_pause(void *data, struct flb_config *config)
{
    struct flb_tail_config *ctx = data;

    /*
     * Pause general collectors:
     *
     * - static : static files lookup before promotion
     */
    flb_input_collector_pause(ctx->coll_fd_static, ctx->i_ins);
    flb_input_collector_pause(ctx->coll_fd_pending, ctx->i_ins);

    if (ctx->multiline == FLB_TRUE) {
        flb_input_collector_pause(ctx->coll_fd_mult_flush, ctx->i_ins);
    }

    /* Pause file system backend handlers */
    flb_tail_fs_pause(ctx);
}

static void in_tail_resume(void *data, struct flb_config *config)
{
    struct flb_tail_config *ctx = data;

    flb_input_collector_resume(ctx->coll_fd_static, ctx->i_ins);
    flb_input_collector_resume(ctx->coll_fd_pending, ctx->i_ins);

    if (ctx->multiline == FLB_TRUE) {
        flb_input_collector_resume(ctx->coll_fd_mult_flush, ctx->i_ins);
    }

    /* Pause file system backend handlers */
    flb_tail_fs_resume(ctx);
}

struct flb_input_plugin in_tail_plugin = {
    .name         = "tail",
    .description  = "Tail files",
    .cb_init      = in_tail_init,
    .cb_pre_run   = in_tail_pre_run,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = in_tail_pause,
    .cb_resume    = in_tail_resume,
    .cb_exit      = in_tail_exit,
    .flags        = 0
};
