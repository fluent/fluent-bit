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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tail_file.h"
#include "tail_config.h"

struct fs_stat {
    /* last time check */
    time_t checked;

    /* previous status */
    struct stat st;
};

static int tail_fs_event(struct flb_config *config, void *in_context)
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
        ret = fstat(file->fd, &st);
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

/* File System events based on stat(2) */
int flb_tail_fs_init(struct flb_input_instance *in,
                     struct flb_tail_config *ctx, struct flb_config *config)
{
    int ret;

    /* Set a manual timer that will be triggered every 0.250 seconds */
    ret = flb_input_set_collector_time(in, tail_fs_event,
                                       0, 250000000, config);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

int flb_tail_fs_add(struct flb_tail_file *file)
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

int flb_tail_fs_remove(struct flb_tail_file *file)
{
    if (file->tail_mode == FLB_TAIL_EVENT) {
        flb_free(file->fs_backend);
    }
    return 0;
}

int flb_tail_fs_exit(struct flb_tail_config *ctx)
{
    (void) ctx;
    return 0;
}
