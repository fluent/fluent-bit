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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_kernel.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sqldb.h>
#include "winlog.h"

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0
#define DEFAULT_BUFFER_SIZE 0x7ffff /* Max size allowed by Win32 (512kb) */

static int in_winlog_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context);

static int in_winlog_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    struct mk_list *head;
    struct winlog_channel *ch;
    struct winlog_config *ctx;

    /* Initialize context */
    ctx = flb_calloc(1, sizeof(struct winlog_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Read Buffer */
    ctx->bufsize = DEFAULT_BUFFER_SIZE;
    ctx->buf = flb_malloc(ctx->bufsize);
    if (!ctx->buf) {
        flb_errno();
        flb_free(ctx);
    }

    /* Open channels */
    tmp = flb_input_get_property("channels", in);
    if (!tmp) {
        flb_plg_debug(ctx->ins, "no channel provided. listening to 'Application'");
        tmp = "Application";
    }

    ctx->active_channel = winlog_open_all(tmp);
    if (!ctx->active_channel) {
        flb_plg_error(ctx->ins, "failed to open channels");
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }

    /* Initialize SQLite DB (optional) */
    tmp = flb_input_get_property("db", in);
    if (tmp) {
        ctx->db = flb_sqldb_open(tmp, in->name, config);
        if (!ctx->db) {
            flb_plg_error(ctx->ins, "could not open/create database");
            winlog_close_all(ctx->active_channel);
            flb_free(ctx->buf);
            flb_free(ctx);
            return -1;
        }

        ret = flb_sqldb_query(ctx->db, SQL_CREATE_CHANNELS, NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "could not create 'channels' table");
            flb_sqldb_close(ctx->db);
            winlog_close_all(ctx->active_channel);
            flb_free(ctx->buf);
            flb_free(ctx);
            return -1;
        }

        mk_list_foreach(head, ctx->active_channel) {
            ch = mk_list_entry(head, struct winlog_channel, _head);
            winlog_sqlite_load(ch, ctx->db);
            flb_plg_debug(ctx->ins, "load channel<%s record=%u time=%u>",
                          ch->name, ch->record_number, ch->time_written);
        }
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set the collector */
    ret = flb_input_set_collector_time(in,
                                       in_winlog_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set up a collector");
    }
    ctx->coll_fd = ret;

    return 0;
}

static int in_winlog_read_channel(struct flb_input_instance *ins,
                                  struct winlog_config *ctx,
                                  struct winlog_channel *ch)
{
    unsigned int read;
    char *ptr;
    PEVENTLOGRECORD evt;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    if (winlog_read(ch, ctx->buf, ctx->bufsize, &read)) {
        flb_plg_error(ctx->ins, "failed to read '%s'", ch->name);
        return -1;
    }
    if (read == 0) {
        return 0;
    }
    flb_plg_debug(ctx->ins, "read %u bytes from '%s'", read, ch->name);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    ptr = ctx->buf;
    while (ptr < ctx->buf + read) {
        evt = (PEVENTLOGRECORD) ptr;

        winlog_pack_event(&mp_pck, evt, ch, ctx);

        ch->record_number = evt->RecordNumber;
        ch->time_written = evt->TimeWritten;

        ptr += evt->Length;
    }

    if (ctx->db) {
        flb_plg_debug(ctx->ins, "save channel<%s record=%u time=%u>",
                      ch->name, ch->record_number, ch->time_written);
        winlog_sqlite_save(ch, ctx->db);
    }

    flb_input_log_append(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);

    msgpack_sbuffer_destroy(&mp_sbuf);
    return 0;
}

static int in_winlog_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    struct winlog_config *ctx = in_context;
    struct mk_list *head;
    struct winlog_channel *ch;

    mk_list_foreach(head, ctx->active_channel) {
        ch = mk_list_entry(head, struct winlog_channel, _head);
        in_winlog_read_channel(ins, ctx, ch);
    }
    return 0;
}

static void in_winlog_pause(void *data, struct flb_config *config)
{
    struct winlog_config *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_winlog_resume(void *data, struct flb_config *config)
{
    struct winlog_config *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int in_winlog_exit(void *data, struct flb_config *config)
{
    struct winlog_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    winlog_close_all(ctx->active_channel);

    if (ctx->db) {
        flb_sqldb_close(ctx->db);
    }
    flb_free(ctx->buf);
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
      0, FLB_TRUE, offsetof(struct winlog_config, interval_sec),
      "Set the polling interval for each channel"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", "0",
      0, FLB_TRUE, offsetof(struct winlog_config, interval_nsec),
      "Set the polling interval for each channel (sub seconds)"
    },
    {
      FLB_CONFIG_MAP_BOOL, "string_inserts", "true",
      0, FLB_TRUE, offsetof(struct winlog_config, string_inserts),
      "Whether to include StringInserts in output records"
    },
    {
      FLB_CONFIG_MAP_BOOL, "use_ansi", "false",
      0, FLB_TRUE, offsetof(struct winlog_config, use_ansi),
      "Use ANSI encoding on eventlog messages"
    },

    /* EOF */
    {0}
};

struct flb_input_plugin in_winlog_plugin = {
    .name         = "winlog",
    .description  = "Windows Event Log",
    .cb_init      = in_winlog_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_winlog_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_winlog_pause,
    .cb_resume    = in_winlog_resume,
    .cb_exit      = in_winlog_exit,
    .config_map   = config_map
};
