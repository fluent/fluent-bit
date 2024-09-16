/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <glob.h>
#include <fnmatch.h>

#include "blob.h"
#include "blob_db.h"
#include "blob_file.h"

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

static int scan_path(struct blob_ctx *ctx)
{
    int i;
    int ret;
    int count = 0;
    glob_t globbuf;
    struct stat st;

    flb_plg_debug(ctx->ins, "scanning path %s", ctx->path);

    /* Safe reset for globfree() */
    globbuf.gl_pathv = NULL;

    /* Scan the given path */
    ret = do_glob(ctx->path, GLOB_TILDE | GLOB_ERR, NULL, &globbuf);
    if (ret != 0) {
        switch (ret) {
        case GLOB_NOSPACE:
            flb_plg_error(ctx->ins, "no memory space available");
            return -1;
        case GLOB_ABORTED:
            flb_plg_error(ctx->ins, "read error, check permissions: %s", ctx->path);
            return -1;
        case GLOB_NOMATCH:
            ret = stat(ctx->path, &st);
            if (ret == -1) {
                flb_plg_debug(ctx->ins, "cannot read info from: %s", ctx->path);
            }
            else {
                ret = access(ctx->path, R_OK);
                if (ret == -1 && errno == EACCES) {
                    flb_plg_error(ctx->ins, "NO read access for path: %s", ctx->path);
                }
                else {
                    flb_plg_debug(ctx->ins, "NO matches for path: %s", ctx->path);
                }
            }
            return 0;
        }
    }

    /* For every entry found, generate an output list */
    for (i = 0; i < globbuf.gl_pathc; i++) {
        ret = stat(globbuf.gl_pathv[i], &st);
        if (ret != 0) {
            flb_plg_debug(ctx->ins, "skip entry=%s", globbuf.gl_pathv[i]);
            continue;
        }

        if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            ret = blob_file_append(ctx, globbuf.gl_pathv[i], &st);
            if (ret == 0) {
                flb_plg_debug(ctx->ins, "blob scan add: %s, inode %" PRIu64,
                              globbuf.gl_pathv[i], (uint64_t) st.st_ino);
            }
            else {
                flb_plg_debug(ctx->ins, "blob scan skip: %s", globbuf.gl_pathv[i]);
            }
        }
        else {
            flb_plg_debug(ctx->ins, "skip entry=%s", globbuf.gl_pathv[i]);
        }
    }

    globfree(&globbuf);
    return count;
}

static int cb_scan_path(struct flb_input_instance *ins,
                        struct flb_config *config, void *in_context)
{
    struct blob_ctx *ctx = in_context;

    return scan_path(ctx);
}

/* Initialize plugin */
static int in_blob_init(struct flb_input_instance *ins,
                        struct flb_config *config, void *data)
{
    int ret;
    struct blob_ctx *ctx;

    /* Allocate space for the configuration context */
    ctx = flb_calloc(1, sizeof(struct blob_ctx));
    if (!ctx) {
        return -1;
    }
    ctx->ins = ins;
    ctx->config = config;
    cfl_list_init(&ctx->files);

    /* laod the config map */
    ret = flb_input_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* associate the context with the instance */
    flb_input_set_context(ins, ctx);

    /* 'path' must be set */
    if (!ctx->path) {
        flb_plg_error(ins, "'path' configuration property is not set");
        flb_free(ctx);
        return -1;
    }

#ifdef FLB_HAVE_SQLDB
    if (ctx->database_file) {
        ctx->db = blob_db_open(ctx, ctx->database_file);
        if (!ctx->db) {
            return -1;
        }
    }
#endif

    /* create a collector to scan the path of files */
    ret = flb_input_set_collector_time(ins,
                                       cb_scan_path,
                                       ctx->scan_refresh_interval, 0,
                                       config);
    if (ret == -1) {
        flb_plg_error(ins, "could not create collector");
        return -1;
    }
    ctx->coll_fd = ret;

    /* initialize the encoder */
    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ctx->log_encoder == NULL) {
        flb_plg_error(ins, "could not initialize event encoder");
        return -1;
    }

    return 0;
}

/* Cleanup serial input */
static int in_blob_exit(void *in_context, struct flb_config *config)
{
    struct blob_ctx *ctx = in_context;

    if (!ctx) {
        return 0;
    }

    blob_db_close(ctx);
    blob_file_list_remove_all(ctx);
    flb_log_event_encoder_destroy(ctx->log_encoder);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "path", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, path),
     "Path to scan for blob/binary files"
    },

#ifdef FLB_HAVE_SQLDB
    {
     FLB_CONFIG_MAP_STR, "database_file", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, database_file),
    },
#endif

    {
     FLB_CONFIG_MAP_TIME, "scan_refresh_interval", "2s",
     0, FLB_TRUE, offsetof(struct blob_ctx, scan_refresh_interval),
     "Set the interval time to scan for new files"
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_blob_plugin = {
    .name         = "blob",
    .description  = "Blob (binary) files",
    .cb_init      = in_blob_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_exit      = in_blob_exit,
    .config_map   = config_map
};
