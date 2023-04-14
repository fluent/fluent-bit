/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_kernel.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sqldb.h>
#include "winevtlog.h"

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0
#define DEFAULT_THRESHOLD_SIZE 0x7ffff /* Default reading buffer size (512kb) */

static int in_winevtlog_collect(struct flb_input_instance *ins,
                                struct flb_config *config, void *in_context);

static int in_winevtlog_init(struct flb_input_instance *in,
                             struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    int read_existing_events = FLB_FALSE;
    struct mk_list *head;
    struct winevtlog_channel *ch;
    struct winevtlog_config *ctx;

    /* Initialize context */
    ctx = flb_calloc(1, sizeof(struct winevtlog_config));
    if (ctx == NULL) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(in, "could not initialize event encoder");
        flb_free(ctx);

        return NULL;
    }

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    /* Set up total reading size threshold */
    ctx->total_size_threshold = DEFAULT_THRESHOLD_SIZE;

    /* Open channels */
    tmp = flb_input_get_property("channels", in);
    if (!tmp) {
        flb_plg_debug(ctx->ins, "no channel provided. listening to 'Application'");
        tmp = "Application";
    }

    ctx->active_channel = winevtlog_open_all(tmp, ctx->read_existing_events, ctx->ignore_missing_channels);
    if (!ctx->active_channel) {
        flb_plg_error(ctx->ins, "failed to open channels");
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    /* Initialize SQLite DB (optional) */
    tmp = flb_input_get_property("db", in);
    if (tmp) {
        ctx->db = flb_sqldb_open(tmp, in->name, config);
        if (!ctx->db) {
            flb_plg_error(ctx->ins, "could not open/create database");
            winevtlog_close_all(ctx->active_channel);
            flb_log_event_encoder_destroy(ctx->log_encoder);
            flb_free(ctx);
            return -1;
        }

        ret = flb_sqldb_query(ctx->db, SQL_CREATE_CHANNELS, NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "could not create 'channels' table");
            flb_sqldb_close(ctx->db);
            winevtlog_close_all(ctx->active_channel);
            flb_log_event_encoder_destroy(ctx->log_encoder);
            flb_free(ctx);
            return -1;
        }

        mk_list_foreach(head, ctx->active_channel) {
            ch = mk_list_entry(head, struct winevtlog_channel, _head);
            winevtlog_sqlite_load(ch, ctx->db);
            flb_plg_debug(ctx->ins, "load channel<%s time=%u>",
                          ch->name, ch->time_created);
        }
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set the collector */
    ret = flb_input_set_collector_time(in,
                                       in_winevtlog_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set up a collector");
    }
    ctx->coll_fd = ret;

    return 0;
}

static int in_winevtlog_read_channel(struct flb_input_instance *ins,
                                     struct winevtlog_config *ctx,
                                     struct winevtlog_channel *ch)
{
    unsigned int read;

    if (winevtlog_read(ch, ctx, &read)) {
        flb_plg_error(ctx->ins, "failed to read '%s'", ch->name);
        return -1;
    }
    if (read == 0) {
        return 0;
    }
    flb_plg_debug(ctx->ins, "read %u bytes from '%s'", read, ch->name);

    if (ctx->db) {
        ch->time_updated = time(NULL);
        flb_plg_debug(ctx->ins, "save channel<%s time=%u>",
                      ch->name, ch->time_updated);
        winevtlog_sqlite_save(ch, ctx->db);
    }

    if (ctx->log_encoder->output_length > 0) {
        flb_input_log_append(ctx->ins, NULL, 0,
                             ctx->log_encoder->output_buffer,
                             ctx->log_encoder->output_length);
    }

    flb_log_event_encoder_reset(ctx->log_encoder);

    return 0;
}

static int in_winevtlog_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    struct winevtlog_config *ctx = in_context;
    struct mk_list *head;
    struct winevtlog_channel *ch;

    mk_list_foreach(head, ctx->active_channel) {
        ch = mk_list_entry(head, struct winevtlog_channel, _head);
        in_winevtlog_read_channel(ins, ctx, ch);
    }
    return 0;
}

static void in_winevtlog_pause(void *data, struct flb_config *config)
{
    struct winevtlog_config *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_winevtlog_resume(void *data, struct flb_config *config)
{
    struct winevtlog_config *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int in_winevtlog_exit(void *data, struct flb_config *config)
{
    struct winevtlog_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    winevtlog_close_all(ctx->active_channel);

    if (ctx->db) {
        flb_sqldb_close(ctx->db);
    }
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_STR, "channels", NULL,
      0, FLB_FALSE, 0,
      "Specify a comma-separated list of channels to read from"
    },
    {
      FLB_CONFIG_MAP_STR, "db", NULL,
      0, FLB_FALSE, 0,
      "Specify DB file to save read offsets"
    },
    {
      FLB_CONFIG_MAP_TIME, "interval_sec", "1s",
      0, FLB_TRUE, offsetof(struct winevtlog_config, interval_sec),
      "Set the polling interval for each channel"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", "0",
      0, FLB_TRUE, offsetof(struct winevtlog_config, interval_nsec),
      "Set the polling interval for each channel (sub seconds)"
    },
    {
      FLB_CONFIG_MAP_BOOL, "string_inserts", "true",
      0, FLB_TRUE, offsetof(struct winevtlog_config, string_inserts),
      "Whether to include StringInserts in output records"
    },
    {
      FLB_CONFIG_MAP_BOOL, "read_existing_events", "false",
      0, FLB_TRUE, offsetof(struct winevtlog_config, read_existing_events),
      "Whether to consume at oldest records in channels"
    },
    {
      FLB_CONFIG_MAP_BOOL, "render_event_as_xml", "false",
      0, FLB_TRUE, offsetof(struct winevtlog_config, render_event_as_xml),
      "Whether to consume at oldest records in channels"
    },
    {
      FLB_CONFIG_MAP_BOOL, "use_ansi", "false",
      0, FLB_TRUE, offsetof(struct winevtlog_config, use_ansi),
      "Use ANSI encoding on eventlog messages"
    },
    {
      FLB_CONFIG_MAP_BOOL, "ignore_missing_channels", "false",
      0, FLB_TRUE, offsetof(struct winevtlog_config, ignore_missing_channels),
      "Whether to ignore channels missing in eventlog"
    },

    /* EOF */
    {0}
};

struct flb_input_plugin in_winevtlog_plugin = {
    .name         = "winevtlog",
    .description  = "Windows EventLog using winevt.h API",
    .cb_init      = in_winevtlog_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_winevtlog_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_winevtlog_pause,
    .cb_resume    = in_winevtlog_resume,
    .cb_exit      = in_winevtlog_exit,
    .config_map   = config_map
};
