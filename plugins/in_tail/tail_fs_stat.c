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

#define _DEFAULT_SOURCE

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "tail_file.h"
#include "tail_db.h"
#include "tail_config.h"
#include "tail_signal.h"

#ifdef FLB_SYSTEM_WINDOWS
#include "win32.h"
#endif

struct fs_stat {
    /* last time check */
    time_t checked;

    /* previous status */
    struct stat st;
};

static int tail_fs_event(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int ret;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file = NULL;
    struct fs_stat *fst;
    struct stat st;
    time_t t;

    t = time(NULL);

    /* Lookup watched file */
    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        fst = file->fs_backend;

        /* Check current status of the file */
        ret = flb_tail_file_stat(file, &st);
        if (ret == -1) {
            flb_errno();
            continue;
        }

        /* Check if the file was modified */
        if ((fst->st.st_mtime != st.st_mtime) ||
            (fst->st.st_size != st.st_size)) {
            /* Update stat info and trigger the notification */
            memcpy(&fst->st, &st, sizeof(struct stat));
            fst->checked = t;
            in_tail_collect_event(file, config);
        }
    }

    return 0;
}

static int tail_fs_check(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int ret;
    int64_t offset;
    char *name;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file = NULL;
    struct fs_stat *fst;
    struct stat st;

    /* Lookup watched file */
    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        fst = file->fs_backend;

        ret = flb_tail_file_stat(file, &st);
        if (ret == -1) {
            flb_plg_debug(ctx->ins, "check: error stat(2) %s, removing", file->name);
            flb_tail_file_remove(file);
            continue;
        }

        /* Check if the file have been deleted */
        if (st.st_nlink == 0) {
            flb_plg_debug(ctx->ins, "file has been deleted: %s", file->name);
#ifdef FLB_HAVE_SQLDB
            if (ctx->db) {
                /* Remove file entry from the database */
                flb_tail_db_file_delete(file, ctx);
            }
#endif
            flb_tail_file_remove(file);
            continue;
        }

        int64_t size_delta = st.st_size - file->size;
        if (size_delta != 0) {
            file->size = st.st_size;
        }

        /* Check if the file was truncated */
        if (size_delta < 0) {
            /* If keeping handle open, it's already open but at wrong offset - seek to beginning */
            if (ctx->keep_file_handle == FLB_TRUE) {
                offset = lseek(file->fd, 0, SEEK_SET);
                if (offset == -1) {
                    flb_errno();
                    return -1;
                }
                file->offset = offset;
            }
            else {
                /* If not keeping handle open, just update offset - handle will be opened/seeks correctly later */
                file->offset = 0;
            }

            flb_plg_debug(ctx->ins, "tail_fs_check: file truncated %s (diff: %"PRId64" bytes)", 
                         file->name, size_delta);
            file->buf_len = 0;
            memcpy(&fst->st, &st, sizeof(struct stat));

#ifdef FLB_HAVE_SQLDB
            /* Update offset in database file */
            if (ctx->db) {
                flb_tail_db_file_offset(file, ctx);
            }
#endif
        }

        if (file->offset < st.st_size) {
            file->pending_bytes = (st.st_size - file->offset);
            tail_signal_pending(ctx);
        }
        else {
            file->pending_bytes = 0;
        }

        /*
         * Skip rotation detection when keep_file_handle is false.
         * Rotation detection requires persistent open handles to work reliably.
         * Without keeping handles open, calling flb_tail_file_name() would
         * unnecessarily open and close handles multiple times per check cycle.
         * Because we are not keeping a handle, a rotation would be interpreted
         * as a truncation and handled by the truncation management logic.
         */
        if (ctx->keep_file_handle == FLB_FALSE) {
            continue;
        }

        /* Discover the current file name for the open file descriptor */
        name = flb_tail_file_name(file);
        if (!name) {
            flb_plg_debug(ctx->ins, "could not resolve %s, removing", file->name);
            flb_tail_file_remove(file);
            continue;
        }

        /*
         * Check if file still exists. This method requires explicity that the
         * user is using an absolute path, otherwise we will be rotating the
         * wrong file.
         *
         * flb_tail_target_file_name_cmp is a deeper compare than
         * flb_tail_file_name_cmp. If applicable, it compares to the underlying
         * real_name of the file.
         */
        if (flb_tail_file_is_rotated(ctx, file) == FLB_TRUE) {
            flb_tail_file_rotated(file);
        }
        flb_free(name);
    }

    return 0;
}

/* File System events based on stat(2) */
int flb_tail_fs_stat_init(struct flb_input_instance *in,
                          struct flb_tail_config *ctx, struct flb_config *config)
{
    int ret;

    flb_plg_debug(ctx->ins, "flb_tail_fs_stat_init() initializing stat tail input");

    /* Set a manual timer to collect events using configured interval */
    /* Convert nanoseconds to seconds and nanoseconds for the API */
    ret = flb_input_set_collector_time(in, tail_fs_event,
                                       (int)(ctx->fstat_interval_nsec / 1000000000L),
                                       (long)(ctx->fstat_interval_nsec % 1000000000L),
                                       config);
    if (ret < 0) {
        return -1;
    }
    ctx->coll_fd_fs1 = ret;

    /* Set a manual timer to check deleted/rotated files every 2.5 seconds */
    ret = flb_input_set_collector_time(in, tail_fs_check,
                                       2, 500000000, config);
    if (ret < 0) {
        return -1;
    }
    ctx->coll_fd_fs2 = ret;

    return 0;
}

void flb_tail_fs_stat_pause(struct flb_tail_config *ctx)
{
    flb_input_collector_pause(ctx->coll_fd_fs1, ctx->ins);
    flb_input_collector_pause(ctx->coll_fd_fs2, ctx->ins);
}

void flb_tail_fs_stat_resume(struct flb_tail_config *ctx)
{
    flb_input_collector_resume(ctx->coll_fd_fs1, ctx->ins);
    flb_input_collector_resume(ctx->coll_fd_fs2, ctx->ins);
}

int flb_tail_fs_stat_add(struct flb_tail_file *file)
{
    int ret;
    struct fs_stat *fst;

    fst = flb_malloc(sizeof(struct fs_stat));
    if (!fst) {
        flb_errno();
        return -1;
    }

    fst->checked = time(NULL);
    ret = stat(file->name, &fst->st);
    if (ret == -1) {
        flb_errno();
        flb_free(fst);
        return -1;
    }
    file->fs_backend = fst;

    return 0;
}

int flb_tail_fs_stat_remove(struct flb_tail_file *file)
{
    if (file->tail_mode == FLB_TAIL_EVENT) {
        flb_free(file->fs_backend);
    }
    return 0;
}

int flb_tail_fs_stat_exit(struct flb_tail_config *ctx)
{
    (void) ctx;
    return 0;
}
