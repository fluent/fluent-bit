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

            matched = PathMatchSpecW(wide_path, wide_pattern);
            flb_free(wide_path);
            flb_free(wide_pattern);

            if (matched) {
                return FLB_TRUE;
            }

            continue;
        }
#endif
        if (PathMatchSpecA(path, pattern->str)) {
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

/*
 * Perform patern match on the given path string. This function
 * supports patterns with "nested" wildcards like below.
 *
 *     tail_scan_pattern("C:\fluent-bit\*\*.txt", ctx);
 *
 * On success, the number of files found is returned (zero indicates
 * "no file found"). On error, -1 is returned.
 */
static int tail_scan_pattern(const char *path, struct flb_tail_config *ctx)
{
    char *star, *p0, *p1;
    char *pattern;
    char *buf;
    int ret;
    int n_added = 0;
    time_t now;
    int64_t mtime;
    size_t prefix_len;
    size_t pattern_len;
    size_t candidate_len;
    HANDLE h;
    WIN32_FIND_DATA data;
    WIN32_FIND_DATAW data_w;
    wchar_t *wide_pattern;
    char *filename;

    if (ctx->windows_path_encoding != FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8) {
        if (strlen(path) > MAX_PATH - 1) {
            flb_plg_error(ctx->ins, "path too long '%s'", path);
            return -1;
        }
    }

    star = strchr(path, '*');
    if (star == NULL) {
        return -1;
    }

    /*
     * C:\data\tmp\input_*.conf
     *            0<-----|
     */
    p0 = star;
    while (path <= p0 && *p0 != '\\') {
        p0--;
    }

    /*
     * C:\data\tmp\input_*.conf
     *                   |---->1
     */
    p1 = star;
    while (*p1 && *p1 != '\\') {
        p1++;
    }

    pattern_len = p1 - path;
    pattern = flb_malloc(pattern_len + 1);
    if (pattern == NULL) {
        flb_errno();
        return -1;
    }

    memcpy(pattern, path, pattern_len);
    pattern[pattern_len] = '\0';

#ifdef FLB_SYSTEM_WINDOWS
    wide_pattern = NULL;
    if (ctx->windows_path_encoding == FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8) {
        wide_pattern = win32_utf8_to_wide(pattern);
        if (wide_pattern == NULL) {
            flb_plg_error(ctx->ins, "invalid UTF-8 path pattern '%s'", pattern);
            flb_free(pattern);
            return -1;
        }

        h = FindFirstFileW(wide_pattern, &data_w);
        flb_free(wide_pattern);
    }
    else {
        h = FindFirstFileA(pattern, &data);
    }
#else
    h = FindFirstFileA(pattern, &data);
#endif
    if (h == INVALID_HANDLE_VALUE) {
        flb_free(pattern);
        return 0;  /* none matched */
    }

    flb_free(pattern);

    now = time(NULL);
    do {
        filename = data.cFileName;
#ifdef FLB_SYSTEM_WINDOWS
        if (ctx->windows_path_encoding == FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8) {
            filename = win32_wide_to_utf8(data_w.cFileName);
            if (filename == NULL) {
                continue;
            }
        }
#endif

        /* Ignore the current and parent dirs */
        if (!strcmp(".", filename) || !strcmp("..", filename)) {
            goto next;
        }

        /* Avoid an infinite loop */
        if (strchr(filename, '*')) {
            goto next;
        }

        prefix_len = p0 - path + 1;
        candidate_len = prefix_len + strlen(filename) + strlen(p1);

        if (ctx->windows_path_encoding != FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8) {
            if (candidate_len > MAX_PATH - 1) {
                flb_plg_warn(ctx->ins, "'%.*s%s%s' is too long",
                             (int) prefix_len, path, filename, p1);
                goto next;
            }
        }

        buf = flb_malloc(candidate_len + 1);
        if (buf == NULL) {
            flb_errno();
            goto next;
        }

        /* Create a path (prefix + filename + suffix) */
        memcpy(buf, path, prefix_len);
        memcpy(buf + prefix_len, filename, strlen(filename));
        memcpy(buf + prefix_len + strlen(filename), p1, strlen(p1));
        buf[candidate_len] = '\0';

        if (strchr(p1, '*')) {
            ret = tail_scan_pattern(buf, ctx); /* recursive */
            if (ret >= 0) {
                n_added += ret;
            }
            flb_free(buf);
            goto next;
        }

        /* Try to register the target file */
        ret = tail_register_file(buf, ctx, now);
        if (ret == 0) {
            n_added++;
        }
        flb_free(buf);

 next:
#ifdef FLB_SYSTEM_WINDOWS
        if (ctx->windows_path_encoding == FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8) {
            flb_free(filename);
        }
#endif
    } while (
#ifdef FLB_SYSTEM_WINDOWS
             ctx->windows_path_encoding == FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8 ?
             FindNextFileW(h, &data_w) != 0 :
#endif
             FindNextFileA(h, &data) != 0);

    FindClose(h);
    return n_added;
}

static int tail_filepath(char *buf, int len, const char *basedir, const char *filename)
{
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];
    char tmp[MAX_PATH];
    int ret;

    ret = _splitpath_s(basedir, drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, NULL, 0);
    if (ret) {
        return -1;
    }

    ret = _splitpath_s(filename, NULL, 0, NULL, 0, fname, _MAX_FNAME, ext, _MAX_EXT);
    if (ret) {
        return -1;
    }

    ret = _makepath_s(tmp, MAX_PATH, drive, dir, fname, ext);
    if (ret) {
        return -1;
    }

    if (_fullpath(buf, tmp, len) == NULL) {
        return -1;
    }

    return 0;
}

static int tail_scan_path(const char *path, struct flb_tail_config *ctx)
{
    int ret;
    int n_added = 0;
    time_t now;

    if (strchr(path, '*')) {
        return tail_scan_pattern(path, ctx);
    }

    /* No wildcard involved. Let's just handle the file... */
    now = time(NULL);
    ret = tail_register_file(path, ctx, now);
    if (ret == 0) {
        n_added++;
    }

    return n_added;
}
