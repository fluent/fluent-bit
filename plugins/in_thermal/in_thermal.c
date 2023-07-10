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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#include <msgpack.h>

#include "in_thermal.h"

struct flb_input_plugin in_thermal_plugin;

/* Default collection time: every 1 second (0 nanoseconds) */
#define DEFAULT_INTERVAL_SEC    "1"
#define DEFAULT_INTERVAL_NSEC   "0"

#define IN_THERMAL_N_MAX          32
#define IN_THERMAL_FILENAME_LEN   1024
#define IN_THERMAL_TYPE_LEN       256

struct temp_info
{
    char   name[IN_THERMAL_FILENAME_LEN]; /*                     .../thermal_zoneX/...  */
    char   type[IN_THERMAL_TYPE_LEN];     /* from /sys/class/thermal/thermal_zoneX/type */
    double temp;                          /* from /sys/class/thermal/thermal_zoneX/temp */
};

/* Retrieve temperature(s) from the system (via /sys/class/thermal) */
static inline int proc_temperature(struct flb_in_thermal_config *ctx,
                                   struct temp_info *info, int n)
{
    int i, j;
    DIR *d;
    struct dirent *e;
    char filename[IN_THERMAL_FILENAME_LEN];
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

        if (e->d_type == DT_REG) {
            continue;
        }

#ifdef FLB_HAVE_REGEX
        if (ctx->name_regex && !flb_regex_match(ctx->name_regex,
                                                (unsigned char *) e->d_name,
                                                strlen(e->d_name))) {
            continue;
        }
#endif

        if (!strncmp(e->d_name, "thermal_zone", 12)) {
            strncpy(info[i].name, e->d_name, IN_THERMAL_FILENAME_LEN);
            if (snprintf(filename, IN_THERMAL_FILENAME_LEN,
                         "/sys/class/thermal/%s/type", e->d_name) <=0 ) {
                continue;
            }

            f = fopen(filename, "r");
            if (!f) {
                flb_errno();
                flb_error("[in_thermal] cannot read %s", filename);
                continue;
            }

            if (f && fgets(info[i].type, IN_THERMAL_TYPE_LEN, f) &&
                strlen(info[i].type) > 1) {
                /* Remove trailing \n */
                for (j = 0; info[i].type[j]; ++j) {
                    if (info[i].type[j] == '\n') {
                        info[i].type[j] = 0;
                        break;
                    }
                }
                fclose(f);

#ifdef FLB_HAVE_REGEX
                if (ctx->type_regex &&
                    !flb_regex_match(ctx->type_regex,
                                     (unsigned char *) info[i].type,
                                     strlen(info[i].type))) {
                    continue;
                }
#endif

                if (snprintf(filename, IN_THERMAL_FILENAME_LEN,
                             "/sys/class/thermal/%s/temp", e->d_name) <= 0) {
                    continue;
                }
                f = fopen(filename, "r");
                if (f && fscanf(f, "%d", &temp) == 1) {
                    info[i].temp = temp/1000.0;
                    ++i;
                }
            }

            if (f) {
                fclose(f);
            }
        }
    }

    closedir(d);
    return i;
}

/* Init temperature input */
static int in_thermal_init(struct flb_input_instance *in,
                       struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_thermal_config *ctx;
    struct temp_info info[IN_THERMAL_N_MAX];
    (void) data;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_thermal_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(in, "could not initialize event encoder");
        flb_free(ctx);

        return -1;
    }

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        flb_plg_error(in, "unable to load configuration");
        return -1;
    }

    /* Collection time setting */
    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
    }

#ifdef FLB_HAVE_REGEX
    if (ctx->name_rgx && strcmp(ctx->name_rgx, "") != 0) {
        ctx->name_regex = flb_regex_create(ctx->name_rgx);
        if (!ctx->name_regex) {
            flb_plg_error(ctx->ins, "invalid 'name_regex' config value");
        }
    }

    if (ctx->type_rgx && strcmp(ctx->type_rgx, "") != 0) {
        ctx->type_regex = flb_regex_create(ctx->type_rgx);
        if (!ctx->type_regex) {
            flb_plg_error(ctx->ins, "invalid 'type_regex' config value");
        }
    }
#endif

    ctx->prev_device_num = proc_temperature(ctx, info,  IN_THERMAL_N_MAX);
    if (!ctx->prev_device_num) {
        flb_plg_warn(ctx->ins, "thermal device file not found");
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set our collector based on time, temperature every 1 second */
    ret = flb_input_set_collector_time(in,
                                       in_thermal_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "Could not set collector for temperature input plugin");

        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);

        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

/* Callback to gather temperature */
int in_thermal_collect(struct flb_input_instance *i_ins,
                   struct flb_config *config, void *in_context)
{
    int n;
    int i;
    int ret;
    struct temp_info info[IN_THERMAL_N_MAX];
    struct flb_in_thermal_config *ctx = in_context;

    (void) config;

    /* Get the current temperature(s) */
    n = proc_temperature(ctx, info, IN_THERMAL_N_MAX);
    if (n != ctx->prev_device_num) {
        flb_plg_info(ctx->ins, "the number of thermal devices changed %d -> %d",
                     ctx->prev_device_num, n);
    }
    ctx->prev_device_num = n;
    if (!n) {
        return 0;
    }

    /*
     * Store the new data into the MessagePack buffer
     */

    for (i = 0; i < n; ++i) {
        ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("name"),
                    FLB_LOG_EVENT_CSTRING_VALUE(info[i].name),

                    FLB_LOG_EVENT_CSTRING_VALUE("type"),
                    FLB_LOG_EVENT_CSTRING_VALUE(info[i].type),

                    FLB_LOG_EVENT_CSTRING_VALUE("temp"),
                    FLB_LOG_EVENT_DOUBLE_VALUE(info[i].temp));
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
        }

        flb_plg_trace(ctx->ins, "%s temperature %0.2f", info[i].name, info[i].temp);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(ctx->ins, NULL, 0,
                             ctx->log_encoder->output_buffer,
                             ctx->log_encoder->output_length);
        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "log event encoding error : %d", ret);

        ret = -1;
    }

    flb_log_event_encoder_reset(ctx->log_encoder);

    return 0;
}

static void in_thermal_pause(void *data, struct flb_config *config)
{
    struct flb_in_thermal_config *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_thermal_resume(void *data, struct flb_config *config)
{
    struct flb_in_thermal_config *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int in_thermal_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_thermal_config *ctx = data;

    if (ctx->log_encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

#ifdef FLB_HAVE_REGEX
    if (ctx && ctx->name_regex) {
        flb_regex_destroy(ctx->name_regex);
    }
    if (ctx && ctx->type_regex) {
        flb_regex_destroy(ctx->type_regex);
    }
#endif

    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_in_thermal_config, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_in_thermal_config, interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
#ifdef FLB_HAVE_REGEX
    {
      FLB_CONFIG_MAP_STR, "name_regex", NULL,
      0, FLB_TRUE, offsetof(struct flb_in_thermal_config, name_rgx),
      "Set thermal name regular expression filter"
    },
    {
      FLB_CONFIG_MAP_STR, "type_regex", NULL,
      0, FLB_TRUE, offsetof(struct flb_in_thermal_config, type_rgx),
      "Set thermal type regular expression filter"
    },
#endif /* FLB_HAVE_REGEX */
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_thermal_plugin = {
    .name         = "thermal",
    .description  = "Thermal",
    .cb_init      = in_thermal_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_thermal_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_thermal_pause,
    .cb_resume    = in_thermal_resume,
    .cb_exit      = in_thermal_exit,
    .config_map   = config_map
};
