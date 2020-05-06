/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_input_plugin.h>
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
    struct flb_slist_entry *pattern;

    if (!ctx->exclude_list) {
        return FLB_FALSE;
    }

    mk_list_foreach(head, ctx->exclude_list) {
        pattern = mk_list_entry(head, struct flb_slist_entry, _head);
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
static int tail_register_file(const char *target, struct flb_tail_config *ctx)
{
    struct stat st;
    char path[MAX_PATH];

    if (_fullpath(path, target, MAX_PATH) == NULL) {
        flb_plg_error(ctx->ins, "cannot get absolute path of %s", target);
        return -1;
    }

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return -1;
    }

    if (tail_is_excluded(path, ctx) == FLB_TRUE) {
        flb_plg_trace(ctx->ins, "skip '%s' (excluded)", path);
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
        flb_plg_error(ctx->ins, "path too long '%s'");
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
            flb_plg_warn(ctx->ins, "'%s%s%s' is too long", buf, data.cFileName, p1);
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
    int n_added;

    flb_plg_debug(ctx->ins, "scanning path %s", pattern);

    n_added = tail_do_scan(pattern, ctx);
    if (n_added >= 0) {
        flb_plg_debug(ctx->ins, "%i files found for '%s'", n_added, pattern);
    }

    return 0;
}

int flb_tail_scan_callback(struct flb_input_instance *ins,
                           struct flb_config *config, void *context)
{
    struct flb_tail_config *ctx = (struct flb_tail_config *) context;
    int n_added;

    n_added = tail_do_scan(ctx->path, ctx);
    if (n_added > 0) {
        flb_plg_debug(ctx->ins, "%i new files found for '%s'",
                      n_added, ctx->path);
        tail_signal_manager(ctx);
    }

    return 0;
}
