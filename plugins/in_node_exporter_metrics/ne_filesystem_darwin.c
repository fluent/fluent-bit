/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <sys/param.h>
#include <sys/mount.h>

#include "ne.h"

static int filesystem_update(struct flb_ne *ctx)
{
    int i;
    int count;
    int skip_flag;
    uint64_t block_size;
    uint64_t blocks;
    uint64_t free_size;
    uint64_t avail_size;
    uint64_t size_bytes;
    uint64_t avail_bytes;
    uint64_t free_bytes;
    uint64_t timestamp;
    char *labels[3];
    struct statfs *mounts;

    count = getmntinfo(&mounts, MNT_NOWAIT);
    if (count == 0) {
        return -1;
    }

    timestamp = cfl_time_now();

    for (i = 0; i < count; i++) {
        skip_flag = flb_regex_match(ctx->fs_regex_skip_fs_types,
                                    (unsigned char *) mounts[i].f_fstypename,
                                    strlen(mounts[i].f_fstypename));
        if (skip_flag) {
            continue;
        }

        skip_flag = flb_regex_match(ctx->fs_regex_skip_mount,
                                    (unsigned char *) mounts[i].f_mntonname,
                                    strlen(mounts[i].f_mntonname));
        if (skip_flag) {
            continue;
        }

        labels[0] = mounts[i].f_mntfromname;
        labels[1] = mounts[i].f_fstypename;
        labels[2] = mounts[i].f_mntonname;

        block_size = (uint64_t) mounts[i].f_bsize;
        blocks = (uint64_t) mounts[i].f_blocks;
        free_size = (uint64_t) mounts[i].f_bfree;
        avail_size = (uint64_t) mounts[i].f_bavail;
        avail_bytes = block_size * avail_size;
        size_bytes = block_size * blocks;
        free_bytes = block_size * free_size;

        cmt_gauge_set(ctx->fs_avail_bytes, timestamp, avail_bytes, 3, labels);
        cmt_gauge_set(ctx->fs_device_error, timestamp, 0, 3, labels);
        cmt_gauge_set(ctx->fs_files, timestamp, (uint64_t) mounts[i].f_files, 3, labels);
        cmt_gauge_set(ctx->fs_files_free, timestamp, (uint64_t) mounts[i].f_ffree, 3, labels);
        cmt_gauge_set(ctx->fs_free_bytes, timestamp, free_bytes, 3, labels);
        cmt_gauge_set(ctx->fs_readonly, timestamp, (mounts[i].f_flags & MNT_RDONLY) ? 1 : 0, 3, labels);
        cmt_gauge_set(ctx->fs_size_bytes, timestamp, size_bytes, 3, labels);
    }

    return 0;
}

static void ne_filesystem_destroy_regexes(struct flb_ne *ctx)
{
    if (ctx->fs_regex_skip_mount != NULL) {
        flb_regex_destroy(ctx->fs_regex_skip_mount);
        ctx->fs_regex_skip_mount = NULL;
    }

    if (ctx->fs_regex_skip_fs_types != NULL) {
        flb_regex_destroy(ctx->fs_regex_skip_fs_types);
        ctx->fs_regex_skip_fs_types = NULL;
    }
}

static int ne_filesystem_init(struct flb_ne *ctx)
{
    ctx->fs_regex_skip_mount = flb_regex_create(ctx->fs_regex_ingore_mount_point_text);
    if (ctx->fs_regex_skip_mount == NULL) {
        goto error;
    }

    ctx->fs_regex_skip_fs_types = flb_regex_create(ctx->fs_regex_ingore_filesystem_type_text);
    if (ctx->fs_regex_skip_fs_types == NULL) {
        goto error;
    }

    ctx->fs_avail_bytes = cmt_gauge_create(ctx->cmt, "node", "filesystem", "avail_bytes",
                                           "Filesystem space available to non-root users in bytes.",
                                           3, (char *[]) {"device", "fstype", "mountpoint"});
    if (ctx->fs_avail_bytes == NULL) {
        goto error;
    }

    ctx->fs_device_error = cmt_gauge_create(ctx->cmt, "node", "filesystem", "device_error",
                                            "Whether an error occurred while getting statistics for the given device.",
                                            3, (char *[]) {"device", "fstype", "mountpoint"});
    if (ctx->fs_device_error == NULL) {
        goto error;
    }

    ctx->fs_files = cmt_gauge_create(ctx->cmt, "node", "filesystem", "files",
                                     "Filesystem total file nodes.",
                                     3, (char *[]) {"device", "fstype", "mountpoint"});
    if (ctx->fs_files == NULL) {
        goto error;
    }

    ctx->fs_files_free = cmt_gauge_create(ctx->cmt, "node", "filesystem", "files_free",
                                          "Filesystem total free file nodes.",
                                          3, (char *[]) {"device", "fstype", "mountpoint"});
    if (ctx->fs_files_free == NULL) {
        goto error;
    }

    ctx->fs_free_bytes = cmt_gauge_create(ctx->cmt, "node", "filesystem", "free_bytes",
                                          "Filesystem free space in bytes.",
                                          3, (char *[]) {"device", "fstype", "mountpoint"});
    if (ctx->fs_free_bytes == NULL) {
        goto error;
    }

    ctx->fs_readonly = cmt_gauge_create(ctx->cmt, "node", "filesystem", "readonly",
                                        "Filesystem read-only status.",
                                        3, (char *[]) {"device", "fstype", "mountpoint"});
    if (ctx->fs_readonly == NULL) {
        goto error;
    }

    ctx->fs_size_bytes = cmt_gauge_create(ctx->cmt, "node", "filesystem", "size_bytes",
                                          "Filesystem size in bytes.",
                                          3, (char *[]) {"device", "fstype", "mountpoint"});
    if (ctx->fs_size_bytes == NULL) {
        goto error;
    }

    return 0;

error:
    ne_filesystem_destroy_regexes(ctx);

    return -1;
}

static int ne_filesystem_update(struct flb_input_instance *ins,
                                struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *) in_context;

    return filesystem_update(ctx);
}

static int ne_filesystem_exit(struct flb_ne *ctx)
{
    ne_filesystem_destroy_regexes(ctx);

    return 0;
}

struct flb_ne_collector filesystem_collector = {
    .name = "filesystem",
    .cb_init = ne_filesystem_init,
    .cb_update = ne_filesystem_update,
    .cb_exit = ne_filesystem_exit
};
