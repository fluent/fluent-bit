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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>

#include <cmetrics/cmt_decode_prometheus.h>
#include "prometheus_textfile.h"

#include <sys/stat.h>
/* Glob support */
#ifndef _MSC_VER
#include <glob.h>
#endif

#ifdef _WIN32
#include <Windows.h>
#include <strsafe.h>
#define PATH_MAX MAX_PATH
#endif

#ifndef _WIN32
static struct cfl_array *read_glob(const char *path)
{
    int ret = -1;
    int ret_glb = -1;
    glob_t glb;
    size_t idx;
    struct cfl_array *list;

    ret_glb = glob(path, GLOB_NOSORT, NULL, &glb);

    if (ret_glb != 0) {
        switch(ret_glb){
        case GLOB_NOSPACE:
            flb_warn("[%s] glob: [%s] no space", __FUNCTION__, path);
            break;
        case GLOB_NOMATCH:
            flb_warn("[%s] glob: [%s] no match", __FUNCTION__, path);
            break;
        case GLOB_ABORTED:
            flb_warn("[%s] glob: [%s] aborted", __FUNCTION__, path);
            break;
        default:
            flb_warn("[%s] glob: [%s] other error", __FUNCTION__, path);
        }
        return NULL;
    }

    list = cfl_array_create(glb.gl_pathc);
    for (idx = 0; idx < glb.gl_pathc; idx++) {
        ret = cfl_array_append_string(list, glb.gl_pathv[idx]);
        if (ret < 0) {
            cfl_array_destroy(list);
            globfree(&glb);
            return NULL;
        }
    }

    globfree(&glb);
    return list;
}
#else
static char *dirname(char *path)
{
    char *ptr;

    ptr = strrchr(path, '\\');

    if (ptr == NULL) {
        return path;
    }
    *ptr++='\0';
    return path;
}

static struct cfl_array *read_glob_win(const char *path, struct cfl_array *list)
{
    char *star, *p0, *p1;
    char pattern[MAX_PATH];
    char buf[MAX_PATH];
    int ret;
    struct stat st;
    HANDLE hnd;
    WIN32_FIND_DATA data;

    if (strlen(path) > MAX_PATH - 1) {
        flb_error("path too long: %s", path);
        return NULL;
    }

    star = strchr(path, '*');
    if (star == NULL) {
        flb_error("path has no wild card: %s", path);
        return NULL;
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

    hnd = FindFirstFileA(pattern, &data);

    if (hnd == INVALID_HANDLE_VALUE) {
        flb_error("unable to open valid handle for: %s", path);
        return NULL;
    }

    if (list == NULL) {
        list = cfl_array_create(3);

        if (list == NULL) {
            flb_error("unable to allocate array");
            FindClose(hnd);
            return NULL;
        }

        /* cfl_array_resizable is hardcoded to return 0. */
        if (cfl_array_resizable(list, FLB_TRUE) != 0) {
            flb_error("unable to make array resizable");
            FindClose(hnd);
            cfl_array_destroy(list);
            return NULL;
        }
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

        if (FAILED(StringCchCatA(buf, MAX_PATH, data.cFileName))) {
            continue;
        }

        if (FAILED(StringCchCatA(buf, MAX_PATH, p1))) {
            continue;
        }

        if (strchr(p1, '*')) {
            if (read_glob_win(path, list) == NULL) {
                cfl_array_destroy(list);
                FindClose(hnd);
                return NULL;
            }
            continue;
        }

        ret = stat(buf, &st);

        if (ret == 0 && (st.st_mode & S_IFMT) == S_IFREG) {
            cfl_array_append_string(list, buf);
        }
    } while (FindNextFileA(hnd, &data) != 0);

    FindClose(hnd);
    return list;
}

static struct cfl_array *read_glob(const char *path)
{
    return read_glob_win(path, NULL);
}
#endif

static int collect_metrics(struct prom_textfile *ctx)
{
    int i;
    int ret;
    char errbuf[256];
    struct stat st;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct cmt *cmt = NULL;
    struct cmt_decode_prometheus_parse_opts opts = {0};
    flb_sds_t content;
    struct cfl_array *files;

    /* cmetrics prometheus decoder options */
    opts.default_timestamp = cfl_time_now();
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);

    /* iterate over configured paths */
    mk_list_foreach(head, ctx->path_list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        files = read_glob(entry->str);
        if (!files) {
            flb_plg_error(ctx->ins, "error reading glob pattern: %s", entry->str);
            continue;
        }
        if (files->entry_count == 0) {
            flb_plg_debug(ctx->ins, "no files found for glob pattern: %s", entry->str);
            cfl_array_destroy(files);
            continue;
        }

        /* iterate files */
        for (i = 0; i < files->entry_count; i++) {
            ret = stat(files->entries[i]->data.as_string, &st);

            /* only process regular files */
            if (ret == 0 && S_ISREG(st.st_mode)) {
                content = flb_file_read(files->entries[i]->data.as_string);
                if (!content) {
                    flb_plg_debug(ctx->ins, "cannot read %s", files->entries[i]->data.as_string);
                    continue;
                }

                if (flb_sds_len(content) == 0) {
                    flb_sds_destroy(content);
                    continue;
                }

                cmt = NULL;
                memset(errbuf, 0, sizeof(errbuf));
                ret = cmt_decode_prometheus_create(&cmt,
                                                   content,
                                                   flb_sds_len(content),
                                                   &opts);
                flb_sds_destroy(content);

                if (ret == 0) {
                    flb_input_metrics_append(ctx->ins, NULL, 0, cmt);
                    cmt_decode_prometheus_destroy(cmt);
                }
                else {
                    flb_plg_error(ctx->ins, "error parsing file %s: '%s'",
                                  files->entries[i]->data.as_string, errbuf);
                    continue;
                }
            }
            else if (ret != 0) {
                flb_plg_error(ctx->ins, "cannot read '%s'", files->entries[i]->data.as_string);
                continue;
            }
        }
        cfl_array_destroy(files);
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

