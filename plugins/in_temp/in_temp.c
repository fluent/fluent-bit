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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#include <msgpack.h>

#include "in_temp.h"

struct flb_input_plugin in_temp_plugin;

#define IN_TEMP_FILENAME_LEN   1024
#define IN_TEMP_TYPE_LEN       256

struct temp_info
{
    char   name[IN_TEMP_FILENAME_LEN]; /*                     .../thermal_zoneX/...  */
    char   type[IN_TEMP_TYPE_LEN];     /* from /sys/class/thermal/thermal_zoneX/type */
    double temp;                       /* from /sys/class/thermal/thermal_zoneX/temp */
};

/* Retrieve temperature(s) from the system (via /sys/class/thermal) */
static inline int proc_temperature(struct temp_info *info, int n)
{
    int i, j;
    DIR *d;
    struct dirent *e;
    char filename[IN_TEMP_FILENAME_LEN];
    FILE *f;
    int temp;

    d = opendir("/sys/class/thermal");
    if (d == NULL) {
        return -1;
    }

    i = 0;
    while (i<n && (e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) {
            continue;
        }

        if (e->d_type==DT_REG) {
            continue;
        }

        if (!strncmp(e->d_name, "thermal_zone", 12)) {
            strncpy(info[i].name, e->d_name, IN_TEMP_FILENAME_LEN);
            if (snprintf(filename, IN_TEMP_FILENAME_LEN, "/sys/class/thermal/%s/type", e->d_name)<=0)
            {
                continue;
            }

            f = fopen(filename, "r");
            if (f && fgets(info[i].type, IN_TEMP_TYPE_LEN, f) && strlen(info[i].type)>1) {
                 /* Remove trailing \n */
                for (j=0; info[i].type[j]; ++j) {
                    if (info[i].type[j]=='\n') {
                        info[i].type[j] = 0;
                        break;
                    }
                }
                fclose(f);

                if (snprintf(filename, IN_TEMP_FILENAME_LEN, "/sys/class/thermal/%s/temp", e->d_name)<=0) {
                    continue;
                }
                f = fopen(filename, "r");
                if (f && fscanf(f, "%d", &temp)==1) {
                    info[i].temp = temp/1000.0;
                    fclose(f);
                    ++i;
                    continue;
                }
            }
            fclose(f);
        }
    }
    closedir(d);
    return i;
}

/* Init temperature input */
static int in_temp_init(struct flb_input_instance *in,
                       struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_temp_config *ctx;
    (void) data;
    const char *pval = NULL;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_temp_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }
    ctx->i_ins = in;

    /* Collection time setting */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        ctx->interval_sec = atoi(pval);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }

    pval = flb_input_get_property("interval_nsec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        ctx->interval_nsec = atoi(pval);
    }
    else {
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set our collector based on time, temperature every 1 second */
    ret = flb_input_set_collector_time(in,
                                       in_temp_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_error("[in_temp] Could not set collector for temperature input plugin");
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

#define IN_TEMP_N_MAX 32

/* Callback to gather temperature */
int in_temp_collect(struct flb_input_instance *i_ins,
                   struct flb_config *config, void *in_context)
{
    int n;
    int i;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    (void) config;
    struct temp_info info[IN_TEMP_N_MAX];

    /* Get the current temperature(s) */
    n = proc_temperature(info, IN_TEMP_N_MAX);
    if (!n) {
        return 0;
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Store the new data into the MessagePack buffer
     */

    for (i=0; i<n; ++i) {
        msgpack_pack_array(&mp_pck, 2);
        flb_pack_time_now(&mp_pck);
        msgpack_pack_map(&mp_pck, 3);

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "name", 4);
        msgpack_pack_str(&mp_pck, strlen(info[i].name));
        msgpack_pack_str_body(&mp_pck, info[i].name, strlen(info[i].name));

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "type", 4);
        msgpack_pack_str(&mp_pck, strlen(info[i].type));
        msgpack_pack_str_body(&mp_pck, info[i].type, strlen(info[i].type));

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "temp", 4);
        msgpack_pack_double(&mp_pck, info[i].temp);

        flb_trace("[in_temp] %s temperature %0.3f%%", info[i].name, info[i].temp);
    }

    flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

static void in_temp_pause(void *data, struct flb_config *config)
{
    struct flb_in_temp_config *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->i_ins);
}

static void in_temp_resume(void *data, struct flb_config *config)
{
    struct flb_in_temp_config *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->i_ins);
}

static int in_temp_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_temp_config *ctx = data;
    flb_free(ctx);
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_temp_plugin = {
    .name         = "temp",
    .description  = "Temperature",
    .cb_init      = in_temp_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_temp_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_temp_pause,
    .cb_resume    = in_temp_resume,
    .cb_exit      = in_temp_exit
};
