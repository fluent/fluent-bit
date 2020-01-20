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

/*
 * This file implements glob-like patch matching feature for Windows
 * based on Win32 API.
 */

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <shlwapi.h>

#include "tail.h"
#include "tail_file.h"
#include "tail_signal.h"
#include "tail_config.h"

static int tail_is_excluded(char *path, struct flb_tail_config *ctx)
{
    struct mk_list *head;
    struct flb_split_entry *pattern;

    if (!ctx->exclude_list) {
        return FLB_FALSE;
    }

    mk_list_foreach(head, ctx->exclude_list) {
        pattern = mk_list_entry(head, struct flb_split_entry, _head);
        if (PathMatchSpecA(path, pattern->value)) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

/*
 * This function is a thin wrapper over flb_tail_file_append(),
 * adding normalization and sanity checks on top of it.
 */
static int tail_register_file(const char *target, struct flb_tail_config *ctx)
{
    struct stat st;
    char path[MAX_PATH];

    if (_fullpath(path, target, MAX_PATH) == NULL) {
        flb_error("[in_tail] cannot get absolute path of %s", target);
        return -1;
    }

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return -1;
    }

    if (tail_is_excluded(path, ctx) == FLB_TRUE) {
        flb_trace("[in_tail] skip '%s' (excluded)", path);
        return -1;
    }

    if (flb_tail_file_exists(path, ctx) == FLB_TRUE) {
        return -1;
    }

    return flb_tail_file_append(path, &st, FLB_TAIL_STATIC, ctx);
}

/*
 * Perform patern match on the given path string. This function
 * supports patterns with "nested" wildcards like below.
 *
 *     tail_scan_pattern("C:\fluent-bit\*\*.txt", ctx);
 */
static int tail_scan_pattern(const char *path, struct flb_tail_config *ctx)
{
    char *star, *p0, *p1;
    char pattern[MAX_PATH];
    char buf[MAX_PATH];
    int ret;
    int n_added = 0;
    HANDLE h;
    WIN32_FIND_DATA data;

    if (strlen(path) > MAX_PATH - 1) {
        flb_error("[in_tail] path too long '%s'");
        return -1;
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

    memcpy(pattern, path, (p1 - path));
    pattern[p1 - path] = '\0';

    h = FindFirstFileA(pattern, &data);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    do {
        /* Ignore the current and parent dirs */
        if (!strcmp(".", data.cFileName) || !strcmp("..", data.cFileName)) {
            continue;
        }

        /* Avoid an infinite loop */
        if (strchr(data.cFileName, '*')) {
            continue;
        }

        /* Create a path (prefix + filename + suffix) */
        memcpy(buf, path, p0 - path + 1);
        buf[p0 - path + 1] = '\0';

        if (strlen(buf) + strlen(data.cFileName) + strlen(p1) > MAX_PATH - 1) {
            flb_warn("[in_tail] '%s%s%s' is too long", buf, data.cFileName, p1);
            continue;
        }
        strcat(buf, data.cFileName);
        strcat(buf, p1);

        if (strchr(p1, '*')) {
            ret = tail_scan_pattern(buf, ctx); /* recursive */
            if (ret >= 0) {
                n_added += ret;
            }
            continue;
        }

        /* Try to register the target file */
        ret = tail_register_file(buf, ctx);
        if (ret == 0) {
            n_added++;
        }
    } while (FindNextFileA(h, &data) != 0);

    FindClose(h);
    return n_added;
}

static int tail_do_scan(const char *path, struct flb_tail_config *ctx)
{
    int ret;
    int n_added = 0;

    if (strchr(path, '*')) {
        return tail_scan_pattern(path, ctx);
    }

    /* No wildcard involved. Let's just handle the file... */
    ret = tail_register_file(path, ctx);
    if (ret == 0) {
        n_added++;
    }

    return n_added;
}

static int tail_exclude_generate(struct flb_tail_config *ctx)
{
    struct mk_list *list;

    /*
     * The exclusion path might content multiple exclusion patterns, first
     * let's split the content into a list.
     */
    list = flb_utils_split(ctx->exclude_path, ',', -1);
    if (!list) {
        return -1;
    }

    if (mk_list_is_empty(list) == 0) {
        return 0;
    }

    /* We use the same list head returned by flb_utils_split() */
    ctx->exclude_list = list;
    return 0;
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

int flb_tail_scan(const char *pattern, struct flb_tail_config *ctx)
{
    HANDLE h;
    WIN32_FIND_DATA found;
    struct stat st;
    char path[MAX_PATH];
    int ret;

    flb_debug("[in_tail] scanning path %s", pattern);

    if (ctx->exclude_path) {
        tail_exclude_generate(ctx);
    }

    h = FindFirstFileA(pattern, &found);
    if (h == INVALID_HANDLE_VALUE) {
        switch (GetLastError()) {
            case ERROR_FILE_NOT_FOUND:
                flb_debug("[in_tail] NO matches for path: %s", pattern);
                return 0;
            default:
                flb_error("[in_tail] Cannot read info from: %s", pattern);
                return -1;
        }
    }

    do {
        /* WIN32_FIND_DATA.cFileName is just a file name, we need to
         * construct a proper path by combining the original pattern.
         */
        ret = tail_filepath(path, MAX_PATH, pattern, found.cFileName);
        if (ret) {
            flb_error("[in_tail] fail to get a path for %s", found.cFileName);
            continue;
        }

        ret = stat(path, &st);
        if (ret == 0 && S_ISREG(st.st_mode)) {
            if (tail_is_excluded(path, ctx) == FLB_TRUE) {
                flb_debug("[in_tail] excluded=%s", path);
                continue;
            }

            flb_tail_file_append(path, &st, FLB_TAIL_STATIC, ctx);
        }
    } while(FindNextFileA(h, &found));

    FindClose(h);
    return 0;
}

int flb_tail_scan_callback(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *context)
{
    HANDLE h;
    WIN32_FIND_DATA found;
    struct stat st;
    struct flb_tail_config *ctx;
    char path[MAX_PATH];
    char *pattern;
    int ret;
    int count = 0;

    ctx = (struct flb_tail_config *) context;
    pattern = ctx->path;

    h = FindFirstFileA(pattern, &found);
    if (h == INVALID_HANDLE_VALUE) {
        switch (GetLastError()) {
            case ERROR_FILE_NOT_FOUND:
                return 0;
            default:
                flb_error("[in_tail] Cannot read info from: %s", pattern);
                return -1;
        }
    }

    do {
        ret = tail_filepath(path, MAX_PATH, pattern, found.cFileName);
        if (ret) {
            flb_error("[in_tail] fail to get a path for %s", found.cFileName);
            continue;
        }

        ret = stat(path, &st);
        if (ret == 0 && S_ISREG(st.st_mode)) {
            if (tail_is_excluded(path, ctx) == FLB_TRUE) {
                continue;
            }
            ret = flb_tail_file_exists(path, ctx);
            if (ret == FLB_TRUE) {
                continue;
            }

            flb_debug("[in_tail] append new file: %s", path);

            flb_tail_file_append(path, &st, FLB_TAIL_STATIC, ctx);

            count++;
        } else {
            flb_debug("[in_tail] skip (invalid) entry=%s", path);
        }
    } while(FindNextFileA(h, &found));

    FindClose(h);

    if (count > 0) {
        tail_signal_manager(ctx);
    }

    return 0;
}
