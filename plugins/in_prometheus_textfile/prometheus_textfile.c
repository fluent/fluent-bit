/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <glob.h>
#include <sys/stat.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>

#include <cmetrics/cmt_decode_prometheus.h>

#include "prometheus_textfile.h"

static int collect_metrics(struct prom_textfile *ctx)
{
    int i;
    int ret;
    glob_t globbuf;
    char errbuf[256];
    struct stat st;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct cmt *cmt = NULL;
    struct cmt_decode_prometheus_parse_opts opts = {0};
    flb_sds_t content;

    /* cmetrics prometheus decoder options */
    opts.default_timestamp = cfl_time_now();
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);

    /* iterate over configured paths */
    mk_list_foreach(head, ctx->path_list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        globbuf.gl_pathc = 0;
        globbuf.gl_pathv = NULL;

        ret = glob(entry->str, 0, NULL, &globbuf);
        if (ret != 0) {
            globfree(&globbuf);
            continue;
        }

        for (i = 0; i < globbuf.gl_pathc; i++) {
            ret = stat(globbuf.gl_pathv[i], &st);

            /* only process regular files */
            if (ret == 0 && S_ISREG(st.st_mode)) {
                content = flb_file_read(globbuf.gl_pathv[i]);
                if (!content) {
                    flb_plg_debug(ctx->ins, "cannot read %s", globbuf.gl_pathv[i]);
                    continue;
                }

                if (flb_sds_len(content) == 0) {
                    flb_sds_destroy(content);
                    continue;
                }

                cmt = NULL;
                ret = cmt_decode_prometheus_create(&cmt,
                                                   content,
                                                   flb_sds_len(content),
                                                   &opts);
                flb_sds_destroy(content);

                if (ret == 0) {
                    flb_input_metrics_append(ctx->ins, NULL, 0, cmt);
                    cmt_decode_prometheus_destroy(cmt);
                }
            }
            else if (ret != 0) {
                flb_plg_error(ctx->ins, "error parsing %s: %s",
                              globbuf.gl_pathv[i], errbuf);
                continue;
            }
        }
        globfree(&globbuf);
    }

    return 0;
}

static int cb_collect(struct flb_input_instance *ins,
                      struct flb_config *config, void *data)
{
    struct prom_textfile *ctx = data;

    collect_metrics(ctx);

    FLB_INPUT_RETURN(0);
}

static int cb_init(struct flb_input_instance *ins,
                   struct flb_config *config, void *data)
{
    int ret;
    struct prom_textfile *ctx;

    ctx = flb_calloc(1, sizeof(struct prom_textfile));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ctx->coll_fd = flb_input_set_collector_time(ins,
                                                cb_collect,
                                                ctx->scrape_interval,
                                                0, config);
    if (ctx->coll_fd < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_input_set_context(ins, ctx);
    return 0;
}

static void cb_pause(void *data, struct flb_config *config)
{
    struct prom_textfile *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void cb_resume(void *data, struct flb_config *config)
{
    struct prom_textfile *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int cb_exit(void *data, struct flb_config *config)
{
    struct prom_textfile *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_CLIST, "path", NULL,
     0, FLB_TRUE, offsetof(struct prom_textfile, path_list),
     "Comma separated list of files or glob patterns to read"
    },
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "10s",
     0, FLB_TRUE, offsetof(struct prom_textfile, scrape_interval),
     "Scraping interval"
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_prometheus_textfile_plugin = {
    .name         = "prometheus_textfile",
    .description  = "Read Prometheus metrics from text files",
    .cb_init      = cb_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_pause,
    .cb_resume    = cb_resume,
    .cb_exit      = cb_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_THREADED | FLB_INPUT_CORO,
};

