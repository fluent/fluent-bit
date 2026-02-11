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
#include <glob.h>
#include <fnmatch.h>
#include <dirent.h>
#include <limits.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>

#include "tail.h"
#include "tail_file.h"
#include "tail_signal.h"
#include "tail_scan.h"
#include "tail_config.h"

/* Define missing GLOB_TILDE if not exists */
#ifndef GLOB_TILDE
#define GLOB_TILDE    1<<2 /* use GNU Libc value */
#define UNSUP_TILDE   1

/* we need these extra headers for path resolution */
#include <limits.h>
#include <sys/types.h>
#include <pwd.h>

static char *expand_tilde(const char *path)
{
    int len;
    char user[256];
    char *p = NULL;
    char *dir = NULL;
    char *tmp = NULL;
    struct passwd *uinfo = NULL;

    if (path[0] == '~') {
        p = strchr(path, '/');

        if (p) {
            /* check case '~/' */
            if ((p - path) == 1) {
                dir = getenv("HOME");
                if (!dir) {
                    return path;
                }
            }
            else {
                /*
                 * it refers to a different user: ~user/abc, first step grab
                 * the user name.
                 */
                len = (p - path) - 1;
                memcpy(user, path + 1, len);
                user[len] = '\0';

                /* use getpwnam() to resolve user information */
                uinfo = getpwnam(user);
                if (!uinfo) {
                    return path;
                }

                dir = uinfo->pw_dir;
            }
        }
        else {
            dir = getenv("HOME");
            if (!dir) {
                return path;
            }
        }

        if (p) {
            tmp = flb_malloc(PATH_MAX);
            if (!tmp) {
                flb_errno();
                return NULL;
            }
            snprintf(tmp, PATH_MAX - 1, "%s%s", dir, p);
        }
        else {
            dir = getenv("HOME");
            if (!dir) {
                return path;
            }

            tmp = flb_strdup(dir);
            if (!tmp) {
                return path;
            }
        }

        return tmp;
    }

    return path;
}
#endif

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

static inline int do_glob(const char *pattern, int flags,
                          void *not_used, glob_t *pglob)
{
    int ret;
    int new_flags;
    char *tmp = NULL;
    int tmp_needs_free = FLB_FALSE;
    (void) not_used;

    /* Save current values */
    new_flags = flags;

    if (flags & GLOB_TILDE) {
#ifdef UNSUP_TILDE
        /*
         * Some libc libraries like Musl do not support GLOB_TILDE for tilde
         * expansion. A workaround is to use wordexp(3) but looking at it
         * implementation in Musl it looks quite expensive:
         *
         *  http://git.musl-libc.org/cgit/musl/tree/src/misc/wordexp.c
         *
         * the workaround is to do our own tilde expansion in a temporary buffer.
         */

        /* Look for a tilde */
        tmp = expand_tilde(pattern);
        if (tmp != pattern) {
            /* the path was expanded */
            pattern = tmp;
            tmp_needs_free = FLB_TRUE;
        }

        /* remove unused flag */
        new_flags &= ~GLOB_TILDE;
#endif
    }

    /* invoke glob with new parameters */
    ret = glob(pattern, new_flags, NULL, pglob);

    /* remove temporary buffer, if allocated by expand_tilde above.
     * Note that this buffer is only used for libc implementations
     * that do not support the GLOB_TILDE flag, like musl. */
    if ((tmp != NULL) && (tmp_needs_free == FLB_TRUE)) {
        flb_free(tmp);
    }

    return ret;
}

static int tail_process_file(char *path, struct stat *st,
                             struct flb_tail_config *ctx, time_t now)
{
    int ret;
    int64_t mtime;
    ssize_t ignored_file_size;

    /* Check if this file is blacklisted */
    if (tail_is_excluded(path, ctx) == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "excluded=%s", path);
        return -1;
    }

    if (ctx->ignore_older > 0) {
        mtime = flb_tail_stat_mtime(st);
        if (mtime > 0) {
            if ((now - ctx->ignore_older) > mtime) {
                flb_plg_debug(ctx->ins, "excluded=%s (ignore_older)",
                              path);

                flb_tail_scan_register_ignored_file_size(
                    ctx,
                    path,
                    strlen(path),
                    st->st_size);

                return -1;
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
    }
    else {
        ignored_file_size = -1;
    }

    /* Append file to list */
    ret = flb_tail_file_append(path, st,
                               FLB_TAIL_STATIC,
                               ignored_file_size,
                               ctx);

    if (ret == 0) {
        flb_plg_debug(ctx->ins, "scan_glob add(): %s, inode %" PRIu64,
                      path, (uint64_t) st->st_ino);
        return 0;
    }
    else {
        flb_plg_debug(ctx->ins, "scan_glob add(): dismissed: %s, inode %" PRIu64,
                      path, (uint64_t) st->st_ino);
    }

    return -1;
}

static int tail_scan_directory(const char *dir, struct flb_tail_config *ctx, time_t now)
{
    int ret;
    int count = 0;
    struct dirent *entry;
    DIR *d;
    char path[PATH_MAX];
    struct stat st;

    d = opendir(dir);
    if (!d) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open directory: %s", dir);
        return -1;
    }

    while ((entry = readdir(d))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        ret = snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        if (ret >= sizeof(path)) {
            flb_plg_warn(ctx->ins, "path too long: %s/%s", dir, entry->d_name);
            continue;
        }

        ret = stat(path, &st);
        if (ret == -1) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            ret = tail_scan_directory(path, ctx, now);
            if (ret > 0) {
                count += ret;
            }
        }
        else if (S_ISREG(st.st_mode)) {
            ret = tail_process_file(path, &st, ctx, now);
            if (ret == 0) {
                count++;
            }
        }
    }

    closedir(d);
    return count;
}

/* Scan a path, register the entries and return how many */
static int tail_scan_path(const char *path, struct flb_tail_config *ctx)
{
    int i;
    int ret;
    int count = 0;
    glob_t globbuf;
    time_t now;
    struct stat st;

    flb_plg_debug(ctx->ins, "scanning path %s", path);

    /* Safe reset for globfree() */
    globbuf.gl_pathv = NULL;

    /* Scan the given path */
    ret = do_glob(path, GLOB_TILDE | GLOB_ERR, NULL, &globbuf);
    if (ret != 0) {
        switch (ret) {
        case GLOB_NOSPACE:
            flb_plg_error(ctx->ins, "no memory space available");
            return -1;
        case GLOB_ABORTED:
            flb_plg_error(ctx->ins, "read error, check permissions: %s", path);
            return -1;
        case GLOB_NOMATCH:
            ret = stat(path, &st);
            if (ret == -1) {
                flb_plg_debug(ctx->ins, "cannot read info from: %s", path);
            }
            else {
                ret = access(path, R_OK);
                if (ret == -1 && errno == EACCES) {
                    flb_plg_error(ctx->ins, "NO read access for path: %s", path);
                }
                else {
                    flb_plg_debug(ctx->ins, "NO matches for path: %s", path);
                }
            }
            return 0;
        }
    }


    /* For every entry found, generate an output list */
    now = time(NULL);
    for (i = 0; i < globbuf.gl_pathc; i++) {
        ret = stat(globbuf.gl_pathv[i], &st);
        if (ret == 0) {
            if (S_ISREG(st.st_mode)) {
                ret = tail_process_file(globbuf.gl_pathv[i], &st, ctx, now);
                if (ret == 0) {
                    count++;
                }
            }
            else if (S_ISDIR(st.st_mode)) {
                if (ctx->recursive == FLB_TRUE) {
                    ret = tail_scan_directory(globbuf.gl_pathv[i], ctx, now);
                    if (ret > 0) {
                        count += ret;
                    }
                }
                else {
                    flb_plg_debug(ctx->ins, "skip directory %s (recursion disabled)",
                                  globbuf.gl_pathv[i]);
                }
            }
            else {
                flb_plg_debug(ctx->ins, "skip (invalid) entry=%s",
                              globbuf.gl_pathv[i]);
            }
        }
    }

    if (count > 0) {
        tail_signal_manager(ctx);
    }

    globfree(&globbuf);
    return count;
}
