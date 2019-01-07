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

#define _DEFAULT_SOURCE

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/inotify.h>

#include "tail_config.h"
#include "tail_file.h"
#include "tail_db.h"
#include "tail_signal.h"

#include <limits.h>
#include <fcntl.h>

static int tail_fs_event(struct flb_input_instance *i_ins,
                         struct flb_config *config, void *in_context)
{
    int ret;
    off_t offset;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file = NULL;
    struct inotify_event ev;
    struct stat st;

    /* Read the event */
    ret  = read(ctx->fd_notify, &ev, sizeof(struct inotify_event));
    if (ret < 1) {
        return -1;
    }

    /* Lookup watched file */
    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        if (file->watch_fd != ev.wd) {
            file = NULL;
            continue;
        }
        break;
    }

    if (!file) {
        return -1;
    }

    /* Check if the file was rotated */
    if (ev.mask & IN_MOVE_SELF) {
        flb_tail_file_rotated(file);
    }

    /* File was removed ? */
    if (ev.mask & IN_ATTRIB) {
        ret = fstat(file->fd, &st);
        if (ret == -1) {
            flb_debug("[in_tail] error stat(2) %s, removing", file->name);
            flb_tail_file_remove(file);
            return 0;
        }

        /* Check if the file have been deleted */
        if (st.st_nlink == 0) {
            flb_debug("[in_tail] removed %s", file->name);
            flb_tail_file_remove(file);
            return 0;
        }
    }

    if (ev.mask & IN_IGNORED) {
        flb_debug("[in_tail] removed %s", file->name);
        flb_tail_file_remove(file);
        return 0;
    }

    if (ev.mask & IN_MODIFY) {
        /*
         * The file was modified, check how many new bytes do
         * we have.
         */
        ret = fstat(file->fd, &st);
        if (ret == -1) {
            flb_errno();
            return -1;
        }

        /* Check if the file was truncated */
        if (file->offset > st.st_size) {
            offset = lseek(file->fd, 0, SEEK_SET);
            if (offset == -1) {
                flb_errno();
                return -1;
            }

            flb_debug("[in_tail] truncated %s", file->name);
            file->offset = offset;
            file->buf_len = 0;

            /* Update offset in the database file */
            if (ctx->db) {
                flb_tail_db_file_offset(file, ctx);
            }
        }

        /* Collect the data */
        ret = in_tail_collect_event(file, config);
        if (ret != FLB_TAIL_ERROR) {
            /*
             * Due to read buffer size capacity, there are some cases where the
             * read operation cannot consume all new data available on one
             * round; upon successfull read(2) some data can still remain.
             *
             * If that is the case, we set in the structure how
             * many bytes are available 'now', so then the further
             * routine that check pending bytes and then the inotified-file
             * can process them properly after an internal signal.
             *
             * The goal to defer this routine is to avoid a blocking
             * read(2) operation, that might kill performance. Just let's
             * wait a second and do a good job.
             */
            if (file->offset < st.st_size) {
                file->pending_bytes = (st.st_size - file->offset);
                tail_signal_pending(ctx);
            }
            else {
                file->pending_bytes = 0;
            }
        }
        return ret;
    }

    return 0;
}

/* File System events based on Inotify(2). Linux >= 2.6.32 is suggested */
int flb_tail_fs_init(struct flb_input_instance *in,
                     struct flb_tail_config *ctx, struct flb_config *config)
{
    int fd;
    int ret;

    /* Create inotify instance */
    fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd == -1) {
        flb_errno();
        return -1;
    }
    flb_debug("[in_tail] inotify watch fd=%i", fd);
    ctx->fd_notify = fd;

    /* This backend use Fluent Bit event-loop to trigger notifications */
    ret = flb_input_set_collector_event(in, tail_fs_event,
                                        ctx->fd_notify, config);
    if (ret < 0) {
        close(fd);
        return -1;
    }
    ctx->coll_fd_fs1 = ret;

    return 0;
}

void flb_tail_fs_pause(struct flb_tail_config *ctx)
{
    flb_input_collector_pause(ctx->coll_fd_fs1, ctx->i_ins);
}

void flb_tail_fs_resume(struct flb_tail_config *ctx)
{
    flb_input_collector_resume(ctx->coll_fd_fs1, ctx->i_ins);
}

int flb_tail_fs_add(struct flb_tail_file *file)
{
    int watch_fd;
    int flags;
    struct flb_tail_config *ctx = file->config;

    /*
     * If there is no watcher associated, we only want to monitor events if
     * this file is rotated to somewhere. Note at this point we are polling
     * lines from the file and once we reach EOF (and a watch_fd exists),
     * we update the flags to receive notifications.
     */
    if (file->watch_fd == -1) {
        flags = IN_ATTRIB | IN_IGNORED | IN_MOVE_SELF;
    }
    else {
        flags = IN_ATTRIB | IN_IGNORED | IN_MODIFY | IN_MOVE_SELF;
    }

    /* Register or update the flags */
    watch_fd = inotify_add_watch(ctx->fd_notify, file->name, flags);
    if (watch_fd == -1) {
        flb_errno();
        return -1;
    }
    file->watch_fd = watch_fd;

    return 0;
}

int flb_tail_fs_remove(struct flb_tail_file *file)
{
    inotify_rm_watch(file->config->fd_notify, file->watch_fd);
    return 0;
}

int flb_tail_fs_exit(struct flb_tail_config *ctx)
{
    (void) ctx;
    return 0;
}
