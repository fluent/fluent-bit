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

/*
 * This file implements glob-like patch matching feature for Windows
 * based on Win32 API.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_file_glob.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>

#include <shlwapi.h>

#include "tail.h"
#include "tail_scan.h"
#include "tail_file.h"
#include "tail_signal.h"
#include "tail_config.h"

#include "win32.h"

static int tail_is_excluded(char *path, struct flb_tail_config *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *pattern;
#ifdef FLB_SYSTEM_WINDOWS
    int matched;
    wchar_t *wide_path;
    wchar_t *wide_pattern;
#endif

    if (!ctx->exclude_list) {
        return FLB_FALSE;
    }

    mk_list_foreach(head, ctx->exclude_list) {
        pattern = mk_list_entry(head, struct flb_slist_entry, _head);
#ifdef FLB_SYSTEM_WINDOWS
        if (ctx->windows_path_encoding == FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8) {
            wide_path = win32_utf8_to_wide(path);
            wide_pattern = win32_utf8_to_wide(pattern->str);
            if (wide_path == NULL || wide_pattern == NULL) {
                flb_free(wide_path);
                flb_free(wide_pattern);
                continue;
            }

            matched = PathMatchSpecW(wide_path, wide_pattern) ||
                      PathMatchSpecW(PathFindFileNameW(wide_path), wide_pattern);
            flb_free(wide_path);
            flb_free(wide_pattern);

            if (matched) {
                return FLB_TRUE;
            }

            continue;
        }
#endif
        if (PathMatchSpecA(path, pattern->str) ||
            PathMatchSpecA(PathFindFileNameA(path), pattern->str)) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

/*
 * This function is a thin wrapper over flb_tail_file_append(),
 * adding normalization and sanity checks on top of it.
 */
static int tail_register_file(const char *target, struct flb_tail_config *ctx,
                              time_t ts)
{
    int ret;
    int64_t mtime;
    struct stat st;
    char legacy_path[MAX_PATH];
    char *path;
    ssize_t ignored_file_size;
    uint64_t aged_out_inode;

    ignored_file_size = -1;
    path = legacy_path;

#ifdef FLB_SYSTEM_WINDOWS
    if (ctx->windows_path_encoding == FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8) {
        path = win32_fullpath_utf8(target);
        if (path == NULL) {
            flb_plg_error(ctx->ins, "cannot get UTF-8 absolute path of %s", target);
            return -1;
        }
    }
    else {
#endif
        if (_fullpath(path, target, MAX_PATH) == NULL) {
            flb_plg_error(ctx->ins, "cannot get absolute path of %s", target);
            return -1;
        }
#ifdef FLB_SYSTEM_WINDOWS
    }
#endif

#ifdef FLB_SYSTEM_WINDOWS
    if (ctx->windows_path_encoding == FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8) {
        ret = win32_stat_utf8(path, &st);
    }
    else {
        ret = stat(path, &st);
    }
#else
    ret = stat(path, &st);
#endif
    if (ret != 0 || !S_ISREG(st.st_mode)) {
        ret = -1;
        goto out;
    }

    if (ctx->ignore_older > 0) {
        mtime = flb_tail_stat_mtime(&st);
        if (mtime > 0) {
            if ((ts - ctx->ignore_older) > mtime) {
                flb_plg_debug(ctx->ins, "excluded=%s (ignore_older)",
                              target);

                flb_tail_scan_register_ignored_file_size(
                    ctx,
                    path,
                    strlen(path),
                    st.st_size);

                ret = -1;
                goto out;
            }
        }
    }

    if (tail_is_excluded(path, ctx) == FLB_TRUE) {
        flb_plg_trace(ctx->ins, "skip '%s' (excluded)", path);
        ret = -1;
        goto out;
    }

    if (ctx->ignore_active_older_files &&
        flb_tail_scan_fetch_aged_out_inode(ctx,
                                           path,
                                           strlen(path),
                                           &aged_out_inode) == 0) {
        if (aged_out_inode == (uint64_t) st.st_ino) {
            mtime = flb_tail_stat_mtime(&st);
            if (mtime > 0 && (ts - ctx->ignore_older) > mtime) {
                flb_plg_debug(ctx->ins, "excluded=%s (ignore_active_older_files)",
                              path);
                ret = -1;
                goto out;
            }
        }
        else {
            /* Different inode at the same path: the stored offset belongs to
             * the old file and must not be applied to the replacement file. */
            flb_tail_scan_unregister_ignored_file_size(ctx, path, strlen(path));
        }

        flb_tail_scan_unregister_aged_out_inode(ctx, path, strlen(path));
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

    ret = flb_tail_file_append(path, &st, FLB_TAIL_STATIC, ignored_file_size, ctx);

 out:
    if (path != legacy_path) {
        flb_free(path);
    }

    return ret;
}

struct tail_glob_scan {
    struct flb_tail_config *ctx;
    time_t now;
    int count;
};

static void tail_scan_match(char *path, void *data)
{
    struct tail_glob_scan *scan = data;

    if (tail_register_file(path, scan->ctx, scan->now) == 0) {
        scan->count++;
    }
}

static int tail_scan_path(const char *path, struct flb_tail_config *ctx)
{
    int ret;
    unsigned int flags = 0;
    struct tail_glob_scan scan = {ctx, time(NULL), 0};

    if (strchr(path, '*') == NULL) {
        return tail_register_file(path, ctx, scan.now) == 0;
    }
    if (ctx->windows_path_encoding == FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8) {
        flags = FLB_FILE_GLOB_WINDOWS_UTF8;
    }

    ret = flb_file_glob(path, flags, tail_scan_match, &scan);
    if (ret != FLB_FILE_GLOB_SUCCESS && ret != FLB_FILE_GLOB_NO_MATCHES) {
        flb_plg_warn(ctx->ins, "glob error %i for path '%s'", ret, path);
        if (scan.count == 0) {
            return -1;
        }
    }

    return scan.count;
}
