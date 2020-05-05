/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <sddl.h>
#include "winlog.h"

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0
#define DEFAULT_BUFFER_SIZE 0x7fff /* Max size allowed by Win32 (32kb) */

struct flb_in_winlog_config {
    unsigned int interval_sec;
    unsigned int interval_nsec;
    unsigned int bufsize;
    char *buf;

    /* Event Log channels */
    struct mk_list *active_channel;

    /* SQLite DB */
    struct flb_sqldb *db;

    /* Collector */
    flb_pipefd_t coll_fd;

    /* Plugin input instance */
    struct flb_input_instance *ins;
};

struct flb_input_plugin in_winlog_plugin;

static int in_winlog_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context);

static int in_winlog_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    struct mk_list *head;
    struct winlog_channel *ch;
    struct flb_in_winlog_config *ctx;

    /* Initialize context */
    ctx = flb_calloc(1, sizeof(struct flb_in_winlog_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    /* Collection time setting */
    ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;

    tmp = flb_input_get_property("interval_sec", in);
    if (tmp != NULL && atoi(tmp) > 0) {
        ctx->interval_sec = atoi(tmp);
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

static int in_winlog_pack_sid(struct flb_in_winlog_config *ctx,
                              msgpack_packer *ppck, PEVENTLOGRECORD evt)
{
    int len;
    char *str;
    char *sid = (char *) evt + evt->UserSidOffset;

    if (!evt->UserSidLength) {
        msgpack_pack_str(ppck, 0);
        msgpack_pack_str_body(ppck, "", 0);
        return 0;
    }

    if (!ConvertSidToStringSidA(sid, &str)) {
        flb_plg_error(ctx->ins, "cannot pack sid (%i)", GetLastError());
        msgpack_pack_str(ppck, 0);
        msgpack_pack_str_body(ppck, "", 0);
        return -1;
    }

    len = strlen(str);
    msgpack_pack_str(ppck, len);
    msgpack_pack_str_body(ppck, str, len);

    LocalFree(str);
    return 0;
}


static int in_winlog_read_channel(struct flb_input_instance *ins,
                                  struct flb_in_winlog_config *ctx,
                                  struct winlog_channel *ch)
{
    int i;
    int ret;
    unsigned int read;
    unsigned int off;
    int len;
    int len_sn;
    int len_cn;
    char *p;
    PEVENTLOGRECORD evt;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    if (winlog_read(ch, ctx->buf, ctx->bufsize, &read)) {
        flb_plg_error(ctx->ins, "failed to read '%s'", ch->name);
        return -1;
    }
    if (read == 0) {
        flb_plg_trace(ctx->ins, "EOF reached on '%s'", ch->name);
        return 0;
    }
    flb_plg_debug(ctx->ins, "read %u bytes from '%s'", read, ch->name);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    p = ctx->buf;
    while (p < ctx->buf + read) {
        evt = (PEVENTLOGRECORD) p;

        /* Update the */
        ch->record_number = evt->RecordNumber;
        ch->time_written = evt->TimeWritten;

        /* Initialize local msgpack buffer */
        msgpack_pack_array(&mp_pck, 2);
        flb_pack_time_now(&mp_pck);

        /* Pack the data */
        msgpack_pack_map(&mp_pck, 11);

        msgpack_pack_str(&mp_pck, 12);
        msgpack_pack_str_body(&mp_pck, "RecordNumber", 12);
        msgpack_pack_uint32(&mp_pck, evt->RecordNumber);

        msgpack_pack_str(&mp_pck, 13);
        msgpack_pack_str_body(&mp_pck, "TimeGenerated", 13);
        msgpack_pack_uint32(&mp_pck, evt->TimeGenerated);

        msgpack_pack_str(&mp_pck, 11);
        msgpack_pack_str_body(&mp_pck, "TimeWritten", 11);
        msgpack_pack_uint32(&mp_pck, evt->TimeWritten);

        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "EventID", 7);
        msgpack_pack_uint32(&mp_pck, evt->EventID);

        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "EventType", 9);
        msgpack_pack_uint16(&mp_pck, evt->EventType);

        msgpack_pack_str(&mp_pck, 13);
        msgpack_pack_str_body(&mp_pck, "EventCategory", 13);
        msgpack_pack_uint16(&mp_pck, evt->EventCategory);

        /* Source Name */
        msgpack_pack_str(&mp_pck, 10);
        msgpack_pack_str_body(&mp_pck, "SourceName", 10);

        len_sn = strlen(p + sizeof(EVENTLOGRECORD));
        msgpack_pack_str(&mp_pck, len_sn);
        msgpack_pack_str_body(&mp_pck, p + sizeof(EVENTLOGRECORD), len_sn);

        /* Computer Name */
        msgpack_pack_str(&mp_pck, 12);
        msgpack_pack_str_body(&mp_pck, "ComputerName", 12);

        len_cn = strlen(p + sizeof(EVENTLOGRECORD) + len_sn + 1);
        msgpack_pack_str(&mp_pck, len_cn);
        msgpack_pack_str_body(&mp_pck, p + sizeof(EVENTLOGRECORD) + len_sn + 1, len_cn);

        /* StringInserts */
        msgpack_pack_str(&mp_pck, 13);
        msgpack_pack_str_body(&mp_pck, "StringInserts", 13);

        msgpack_pack_array(&mp_pck, evt->NumStrings);

        off = evt->StringOffset;
        for (i = 0; i < evt->NumStrings; i++) {
            len = strlen(p + off);
            msgpack_pack_str(&mp_pck, len);
            msgpack_pack_str_body(&mp_pck, p + off , len);
            off += len + 1;
        }

        /* Sid */
        msgpack_pack_str(&mp_pck, 3);
        msgpack_pack_str_body(&mp_pck, "Sid", 3);
        in_winlog_pack_sid(ctx, &mp_pck, evt);

        /* Data */
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "Data", 4);
        msgpack_pack_bin(&mp_pck, evt->DataLength);
        msgpack_pack_bin_body(&mp_pck, p + evt->DataOffset, evt->DataLength);

        p += evt->Length;
    }

    if (ctx->db) {
        flb_plg_debug(ctx->ins, "save channel<%s record=%u time=%u>",
                      ch->name, ch->record_number, ch->time_written);
        winlog_sqlite_save(ch, ctx->db);
    }

    flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);

    msgpack_sbuffer_destroy(&mp_sbuf);
    return 0;
}

static int in_winlog_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    struct flb_in_winlog_config *ctx = in_context;
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
    struct flb_in_winlog_config *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_winlog_resume(void *data, struct flb_config *config)
{
    struct flb_in_winlog_config *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int in_winlog_exit(void *data, struct flb_config *config)
{
    struct flb_in_winlog_config *ctx = data;

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

struct flb_input_plugin in_winlog_plugin = {
    .name         = "winlog",
    .description  = "Windows Event Log",
    .cb_init      = in_winlog_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_winlog_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_winlog_pause,
    .cb_resume    = in_winlog_resume,
    .cb_exit      = in_winlog_exit
};
