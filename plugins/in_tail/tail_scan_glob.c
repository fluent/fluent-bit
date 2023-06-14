/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <glob.h>
#include <fnmatch.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_file.h>

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

/* Scan a path, register the entries and return how many */
static int tail_scan_path(const char *path, struct flb_tail_config *ctx)
{
    int ret;
    int count;
    time_t now;
    int64_t mtime;
    struct flb_file_stat st;
    struct flb_file_glob_context glob_context;
    uint64_t glob_flags;
    char *file_path;

    flb_plg_debug(ctx->ins, "scanning path %s", path);

    glob_flags = FLB_FILE_GLOB_ABORT_ON_ERROR | FLB_FILE_GLOB_EXPAND_TILDE;

    ret = flb_file_glob_start(&glob_context, path, glob_flags   );

    if (ret != FLB_FILE_GLOB_ERROR_SUCCESS) {
        if (ret == FLB_FILE_GLOB_ERROR_NO_MEMORY) {
            flb_plg_error(ctx->ins, "no memory space available");
        }
        else if (ret == FLB_FILE_GLOB_ERROR_ABORTED) {
            flb_plg_error(ctx->ins, "read error, check permissions: %s", path);
        }
        else if (ret == FLB_FILE_GLOB_ERROR_NO_FILE) {
            flb_plg_debug(ctx->ins, "cannot read info from: %s", path);
        }
        else if (ret == FLB_FILE_GLOB_ERROR_NO_ACCESS) {
            flb_plg_error(ctx->ins, "no read access for path: %s", path);
        }
        else if (ret == FLB_FILE_GLOB_ERROR_NO_MATCHES) {
            flb_plg_debug(ctx->ins, "no matches for path: %s", path);
        }
        else if (ret == FLB_FILE_GLOB_ERROR_OVERSIZED_PATH) {
            flb_plg_debug(ctx->ins, "oversized path or entry: %s", path);
        }

        flb_file_glob_clean(&glob_context);

        return -1;
    }

    now = time(NULL);
    count = 0;

    while (flb_file_glob_fetch(&glob_context, &file_path) ==
            FLB_FILE_GLOB_ERROR_SUCCESS) {
        ret = flb_file_stat(file_path, &st);

        if (ret == 0 && FLB_FILE_ISREG(st.mode)) {
            /* Check if this file is blacklisted */
            if (tail_is_excluded(file_path, ctx) == FLB_TRUE) {
                flb_plg_debug(ctx->ins, "excluded=%s", file_path);
                continue;
            }

            if (ctx->ignore_older > 0) {
                mtime = st.modification_time;
                if (mtime > 0) {
                    if ((now - ctx->ignore_older) > mtime) {
                        flb_plg_debug(ctx->ins, "excluded=%s (ignore_older)",
                                      file_path);
                        continue;
                    }
                }
            }

            /* Append file to list */
            ret = flb_tail_file_append(file_path, &st,
                                       FLB_TAIL_STATIC, ctx);
            if (ret == 0) {
                flb_plg_debug(ctx->ins,
                              "scan_glob add(): %s, inode %"PRIu64,
                              file_path,
                              (uint64_t) st.inode);

                count++;
            }
            else {
                flb_plg_debug(ctx->ins,
                              "scan_blog add(): dismissed: %s, inode %"PRIu64,
                              file_path,
                              (uint64_t) st.inode);
            }
        }
        else {
            flb_plg_debug(ctx->ins, "skip (invalid) entry=%s",
                          file_path);
        }
    }

/*
    I removed the call to tail_signal_manager because  flb_tail_file_append
    does emit a signal when the file is appended with FLB_TAIL_STATIC as its
    mode.
*/

    flb_file_glob_clean(&glob_context);

    return count;
}
