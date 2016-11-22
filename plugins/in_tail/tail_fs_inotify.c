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

#define _DEFAULT_SOURCE

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/inotify.h>

#include "tail_config.h"
#include "tail_file.h"

static int tail_fs_event(struct flb_config *config, void *in_context)
{
    int ret;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file = NULL;
    struct inotify_event ev;

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

    return in_tail_collect_event(file, config);
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
    if (ret != 0) {
        close(fd);
        return -1;
    }

    return 0;
}

int flb_tail_fs_add(struct flb_tail_file *file)
{
    int watch_fd;
    struct flb_tail_config *ctx = file->config;

    /* Register the file into Inotify */
    watch_fd = inotify_add_watch(ctx->fd_notify, file->name,
                                 IN_MODIFY | IN_MOVED_TO);
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
    close(file->watch_fd);

    return 0;
}

int flb_tail_fs_exit(struct flb_tail_config *ctx)
{
    (void) ctx;
    return 0;
}
