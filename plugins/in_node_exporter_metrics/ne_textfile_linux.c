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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_file.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>
#include <float.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Prometheus decoder */
#include <cmetrics/cmt_decode_prometheus.h>
#include "cmt_decode_prometheus_parser.h"

static char *error_reason(int cmt_error)
{
    static char *reason = NULL;

    switch(cmt_error) {
    case CMT_DECODE_PROMETHEUS_SYNTAX_ERROR:
        reason = "syntax error";
        break;
    case CMT_DECODE_PROMETHEUS_ALLOCATION_ERROR:
        reason = "allocation error";
        break;
    case CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT_EXCEEDED:
        reason = "max label count exceeded";
        break;
    case CMT_DECODE_PROMETHEUS_CMT_SET_ERROR:
        reason = "cmt set error";
        break;
    case CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR:
        reason = "cmt create error";
        break;
    case CMT_DECODE_PROMETHEUS_PARSE_VALUE_FAILED:
        reason = "parse value failed";
        break;
    case CMT_DECODE_PROMETHEUS_PARSE_TIMESTAMP_FAILED:
        reason = "parse timestamp failed";
        break;
    default:
        reason = "unknown reason";
    }

    return reason;
}

static int textfile_update(struct flb_ne *ctx)
{
    int ret;
    char errbuf[256];
    flb_sds_t contents;
    struct cmt_decode_prometheus_parse_opts opts;
    uint64_t timestamp;
    struct cmt *cmt;
    struct mk_list *head;
    struct mk_list list;
    struct flb_slist_entry *entry;
    const char *nop_pattern = "";
    const char *dir_pattern = "/*.prom";
    char *ext;
    struct stat st;
    int use_directory_pattern = FLB_FALSE;

    timestamp = cfl_time_now();

    memset(&opts, 0, sizeof(opts));
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);
    opts.default_timestamp = timestamp;

    flb_plg_debug(ctx->ins, "scanning path %s", ctx->path_textfile);

    if (ctx->path_textfile == NULL) {
        flb_plg_warn(ctx->ins, "No valid path for textfile metric is registered");
        return -1;
    }

    ext = strrchr(ctx->path_textfile, '.');
    if (ext != NULL) {
        if (strncmp(ext, ".prom", 5) == 0) {
            flb_plg_debug(ctx->ins, "specified path %s has \".prom\" extension",
                          ctx->path_textfile);
            use_directory_pattern = FLB_FALSE;
        }
        else {
            ret = stat(ctx->path_textfile, &st);
            if (ret != 0) {
                flb_plg_warn(ctx->ins, "specified path %s is not accesible",
                             ctx->path_textfile);
            }
            if (S_ISREG(st.st_mode)) {
                flb_plg_warn(ctx->ins, "specified path %s does not have \".prom\" extension. Assuming directory",
                             ctx->path_textfile);
                use_directory_pattern = FLB_TRUE;
            }
        }
    }
    else {
        flb_plg_debug(ctx->ins, "specified file path %s does not have extension part. Globbing directory with \"%s\" suffix",
                      ctx->path_textfile, dir_pattern);
        use_directory_pattern = FLB_TRUE;
    }

    if (use_directory_pattern == FLB_TRUE) {
        /* Scan the given directory path */
        ret = ne_utils_path_scan(ctx, ctx->path_textfile, dir_pattern, NE_SCAN_FILE, &list);
        if (ret != 0) {
            return -1;
        }
    }
    else {
        /* Scan the given file path */
        ret = ne_utils_path_scan(ctx, ctx->path_textfile, nop_pattern, NE_SCAN_FILE, &list);
        if (ret != 0) {
            return -1;
        }
    }

    /* Process entries */
    mk_list_foreach(head, &list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        /* Update metrics from text file */
        contents = flb_file_read_contents(entry->str);
        if (contents == NULL) {
            flb_plg_debug(ctx->ins, "skip invalid file of prometheus: %s",
                          entry->str);
            continue;
        }

        if (flb_sds_len(contents) == 0) {
            flb_plg_debug(ctx->ins, "skip empty payload of prometheus: %s",
                          entry->str);
            continue;
        }

        ret = cmt_decode_prometheus_create(&cmt, contents, flb_sds_len(contents), &opts);
        if (ret == 0) {
            flb_plg_debug(ctx->ins, "parse a payload of prometheus: %s",
                          entry->str);
            cmt_cat(ctx->cmt, cmt);
            cmt_decode_prometheus_destroy(cmt);
        }
        else {
            flb_plg_debug(ctx->ins, "parse a payload of prometheus: dismissed: %s, error: %d",
                          entry->str, ret);
            cmt_counter_set(ctx->load_errors, timestamp, 1.0, 1,  (char*[]){error_reason(ret)});
        }
        flb_sds_destroy(contents);
    }
    flb_slist_destroy(&list);

    return 0;
}

static int ne_textfile_init(struct flb_ne *ctx)
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

static int ne_textfile_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    textfile_update(ctx);

    return 0;
}

static int ne_textfile_exit(struct flb_ne *ctx)
{
    return 0;
}

struct flb_ne_collector textfile_collector = {
    .name = "textfile",
    .cb_init = ne_textfile_init,
    .cb_update = ne_textfile_update,
    .cb_exit = ne_textfile_exit
};
