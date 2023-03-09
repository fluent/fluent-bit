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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_file.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>
#include <float.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glob.h>

/* Prometheus decoder */
#include <cmetrics/cmt_decode_prometheus.h>
#include "cmt_decode_prometheus_parser.h"

static inline int do_glob(const char *pattern, int flags,
                          void *not_used, glob_t *pglob)
{
    int ret;
    (void) not_used;

    /* invoke glob with parameters */
    ret = glob(pattern, flags, NULL, pglob);

    return ret;
}

static int textfile_update(struct flb_ne *ctx)
{
    int i;
    int ret;
    glob_t globbuf;
    char errbuf[256];
    struct stat st;
    flb_sds_t contents;
    struct cmt_decode_prometheus_parse_opts opts;
    uint64_t timestamp;
    char *error_reason;
    struct cmt *cmt;
    char *ext;

    timestamp = cfl_time_now();

    memset(&opts, 0, sizeof(opts));
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);
    opts.default_timestamp = timestamp;

    flb_plg_debug(ctx->ins, "scanning path %s", ctx->path_textfile);

    /* Safe reset for globfree() */
    globbuf.gl_pathv = NULL;

    if (ctx->path_textfile == NULL) {
        flb_plg_warn(ctx->ins, "No valid path for textfile metric is registered");
    }

    /* Scan the given path */
    ret = do_glob(ctx->path_textfile, GLOB_TILDE | GLOB_ERR, NULL, &globbuf);
    if (ret != 0) {
        switch (ret) {
        case GLOB_NOSPACE:
            flb_plg_error(ctx->ins, "no memory space available");
            return -1;
        case GLOB_ABORTED:
            flb_plg_error(ctx->ins, "read error, check permissions: %s", ctx->path_textfile);
            return -1;
        case GLOB_NOMATCH:
            ret = stat(ctx->path_textfile, &st);
            if (ret == -1) {
                flb_plg_debug(ctx->ins, "cannot read info from: %s", ctx->path_textfile);
            }
            else {
                ret = access(ctx->path_textfile, R_OK);
                if (ret == -1 && errno == EACCES) {
                    flb_plg_error(ctx->ins, "NO read access for path: %s", ctx->path_textfile);
                }
                else {
                    flb_plg_debug(ctx->ins, "NO matches for path: %s", ctx->path_textfile);
                }
            }
            return 0;
        }
    }

    for (i = 0; i < globbuf.gl_pathc; i++) {
        ret = stat(globbuf.gl_pathv[i], &st);
        if (ret == 0 && S_ISREG(st.st_mode)) {
            ext = strrchr(globbuf.gl_pathv[i], '.');
            if (ext == NULL) {
                flb_plg_warn(ctx->ins, "globbed file %s does not have extension part",
                             globbuf.gl_pathv[i]);
                continue;
            }
            if (strncmp(ext, ".prom", 5) != 0) {
                flb_plg_warn(ctx->ins, "globbed file %s does not have \".prom\" extension",
                             globbuf.gl_pathv[i]);
                continue;
            }
            /* Update metrics from text file */
            contents = flb_file_read(globbuf.gl_pathv[i]);
            if (flb_sds_len(contents) == 0) {
                flb_plg_debug(ctx->ins, "skip empty payload of prometheus: %s, inode %li",
                              globbuf.gl_pathv[i], st.st_ino);
                continue;
            }

            ret = cmt_decode_prometheus_create(&cmt, contents, 0, &opts);
            if (ret == 0) {
                flb_plg_debug(ctx->ins, "parse a payload of prometheus: %s, inode %li",
                              globbuf.gl_pathv[i], st.st_ino);
                cmt_cat(ctx->cmt, cmt);
            }
            else {
                flb_plg_debug(ctx->ins, "parse a payload of prometheus: dismissed: %s, inode %li, error: %d",
                              globbuf.gl_pathv[i], st.st_ino, ret);
                switch(ret) {
                case CMT_DECODE_PROMETHEUS_SYNTAX_ERROR:
                    error_reason = "syntax error";
                    break;
                case CMT_DECODE_PROMETHEUS_ALLOCATION_ERROR:
                    error_reason = "allocation error";
                    break;
                case CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT_EXCEEDED:
                    error_reason = "max label count exceeded";
                    break;
                case CMT_DECODE_PROMETHEUS_CMT_SET_ERROR:
                    error_reason = "cmt set error";
                    break;
                case CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR:
                    error_reason = "cmt create error";
                    break;
                case CMT_DECODE_PROMETHEUS_PARSE_VALUE_FAILED:
                    error_reason = "parse value failed";
                    break;
                case CMT_DECODE_PROMETHEUS_PARSE_TIMESTAMP_FAILED:
                    error_reason = "parse timestamp failed";
                    break;
                default:
                    error_reason = "unknown reason";
                }
                cmt_counter_set(ctx->load_errors, timestamp, 1.0, 1,  (char*[]){error_reason});
            }
            flb_sds_destroy(contents);
            cmt_decode_prometheus_destroy(cmt);
        }
        else {
            flb_plg_debug(ctx->ins, "skip (invalid) entry=%s",
                          globbuf.gl_pathv[i]);
        }
    }

    globfree(&globbuf);
    return 0;
}

int ne_textfile_init(struct flb_ne *ctx)
{
    ctx->load_errors = cmt_counter_create(ctx->cmt,
                                          "node",
                                          "textfile",
                                          "node_textfile_scrape_error",
                                          "Greater equal than 1 if there was an error opening, reading, or parsing a file, 0 otherwise.",
                                          1, (char *[]) {"reason"});

    if (ctx->load_errors == NULL) {
        return -1;
    }

    return 0;
}

int ne_textfile_update(struct flb_ne *ctx)
{
    textfile_update(ctx);

    return 0;
}

int ne_textfile_exit(struct flb_ne *ctx)
{
    return 0;
}
