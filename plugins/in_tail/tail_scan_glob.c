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

#include <sys/types.h>
#include <sys/stat.h>
#include <fnmatch.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_file_glob.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>

#include "tail.h"
#include "tail_file.h"
#include "tail_signal.h"
#include "tail_scan.h"
#include "tail_config.h"

static int tail_is_excluded(char *path, struct flb_tail_config *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *pattern;

    if (!ctx->exclude_list) {
        return FLB_FALSE;
    }

    mk_list_foreach(head, ctx->exclude_list) {
        pattern = mk_list_entry(head, struct flb_slist_entry, _head);
        if (fnmatch(pattern->str, path, 0) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

struct tail_glob_scan {
    struct flb_tail_config *ctx;
    time_t now;
    bool time_sampled;
    int count;
};

static void tail_scan_match(char *path, void *data)
{
    struct tail_glob_scan *scan = data;
    struct flb_tail_config *ctx = scan->ctx;
    int ret;
    int64_t mtime;
    struct stat st;
    ssize_t ignored_file_size = -1;
    uint64_t aged_out_inode;

    /* POSIX enumeration has finished by the time the first match arrives. */
    if (!scan->time_sampled) {
        scan->now = time(NULL);
        scan->time_sampled = true;
    }

    if (ctx->follow_symlinks) {
        ret = stat(path, &st);
    }
    else {
        ret = lstat(path, &st);
    }
    if (ret == 0 && S_ISREG(st.st_mode)) {
        /* Check if this file is blacklisted */
        if (tail_is_excluded(path, ctx) == FLB_TRUE) {
            flb_plg_debug(ctx->ins, "excluded=%s", path);
            return;
        }

        if (ctx->ignore_active_older_files &&
            flb_tail_scan_fetch_aged_out_inode(ctx,
                                               path,
                                               strlen(path),
                                               &aged_out_inode) == 0) {
            if (aged_out_inode == (uint64_t) st.st_ino) {
                mtime = flb_tail_stat_mtime(&st);
                if (mtime > 0 && (scan->now - ctx->ignore_older) > mtime) {
                    flb_plg_debug(ctx->ins,
                                  "excluded=%s (ignore_active_older_files)",
                                  path);
                    return;
                }
            }
            else {
                /* Different inode at the same path: the stored offset
                 * belongs to the old file and must not be applied to the
                 * replacement file. */
                flb_tail_scan_unregister_ignored_file_size(
                    ctx,
                    path,
                    strlen(path));
            }

            flb_tail_scan_unregister_aged_out_inode(
                ctx,
                path,
                strlen(path));
        }

        if (ctx->ignore_older > 0) {
            mtime = flb_tail_stat_mtime(&st);
            if (mtime > 0) {
                if ((scan->now - ctx->ignore_older) > mtime) {
                    flb_plg_debug(ctx->ins, "excluded=%s (ignore_older)",
                                  path);

                    flb_tail_scan_register_ignored_file_size(
                        ctx,
                        path,
                        strlen(path),
                        st.st_size);

                    return;
                }
            }
        }

        if (ctx->ignore_older > 0) {
            ignored_file_size = flb_tail_scan_fetch_ignored_file_size(
                                    ctx,
                                    path,
                                    strlen(path));

            flb_tail_scan_unregister_ignored_file_size(
                ctx,
                path,
                strlen(path));

            /* Discard stale offset if the file was truncated in place. */
            if (ignored_file_size > (ssize_t) st.st_size) {
                ignored_file_size = -1;
            }
        }

        /* Append file to list */
        ret = flb_tail_file_append(path, &st,
                                   FLB_TAIL_STATIC,
                                   ignored_file_size,
                                   ctx);

        if (ret == 0) {
            flb_plg_debug(ctx->ins, "scan_glob add(): %s, inode %" PRIu64,
                          path, (uint64_t) st.st_ino);
            scan->count++;
        }
        else {
            flb_plg_debug(ctx->ins, "scan_blog add(): dismissed: %s, inode %" PRIu64,
                          path, (uint64_t) st.st_ino);
        }
    }
    else {
        flb_plg_debug(ctx->ins, "skip (invalid) entry=%s",
                      path);
    }
}

static int tail_scan_path(const char *path, struct flb_tail_config *ctx)
{
    int ret;
    struct stat st;
    struct tail_glob_scan scan = {.ctx = ctx};

    flb_plg_debug(ctx->ins, "scanning path %s", path);
    ret = flb_file_glob(path, FLB_FILE_GLOB_EXPAND_TILDE, tail_scan_match, &scan);
    switch (ret) {
    case FLB_FILE_GLOB_SUCCESS:
        break;
    case FLB_FILE_GLOB_NO_MATCHES:
        if (stat(path, &st) == -1) {
            flb_plg_debug(ctx->ins, "cannot read info from: %s", path);
        }
        else if (access(path, R_OK) == -1 && errno == EACCES) {
            flb_plg_error(ctx->ins, "NO read access for path: %s", path);
        }
        else {
            flb_plg_debug(ctx->ins, "NO matches for path: %s", path);
        }
        return 0;
    case FLB_FILE_GLOB_NO_MEMORY:
        flb_plg_error(ctx->ins, "no memory space available");
        return -1;
    default:
        flb_plg_error(ctx->ins, "read error, check permissions: %s", path);
        return -1;
    }

    if (scan.count > 0) {
        tail_signal_manager(ctx);
    }

    return scan.count;
}
