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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_time.h>

#include "systemd_config.h"
#include "systemd_db.h"

/* msgpack helpers to pack unsigned ints (it takes care of endianness */
#define pack_uint16(buf, d) _msgpack_store16(buf, (uint16_t) d)
#define pack_uint32(buf, d) _msgpack_store32(buf, (uint32_t) d)

/* tag composer */
static int tag_compose(const char *tag, const char *unit_name,
                       int unit_size, char **out_buf, size_t *out_size)
{
    int len;
    const char *p;
    char *buf = *out_buf;
    size_t buf_s = 0;

    p = strchr(tag, '*');
    if (!p) {
        return -1;
    }

    /* Copy tag prefix if any */
    len = (p - tag);
    if (len > 0) {
        memcpy(buf, tag, len);
        buf_s += len;
    }

    /* Append file name */
    memcpy(buf + buf_s, unit_name, unit_size);
    buf_s += unit_size;

    /* Tag suffix (if any) */
    p++;
    if (*p) {
        len = strlen(tag);
        memcpy(buf + buf_s, p, (len - (p - tag)));
        buf_s += (len - (p - tag));
    }

    buf[buf_s] = '\0';
    *out_size = buf_s;

    return 0;
}

static int in_systemd_collect(struct flb_input_instance *ins,
                              struct flb_config *config, void *in_context)
{
    int ret;
    int ret_j;
    int len;
    int entries = 0;
    int rows = 0;
    time_t sec;
    long nsec;
    uint8_t h;
    uint64_t usec;
    size_t length;
    const char *sep;
    const char *key;
    const char *val;
    char *tmp;
#ifdef FLB_HAVE_SQLDB
    char *cursor = NULL;
#endif
    char *tag = NULL;
    char new_tag[PATH_MAX];
    char last_tag[PATH_MAX];
    size_t tag_len;
    size_t last_tag_len = 0;
    off_t off;
    const void *data;
    struct flb_systemd_config *ctx = in_context;
    struct flb_time tm;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /* Restricted by mem_buf_limit */
    if (flb_input_buf_paused(ins) == FLB_TRUE) {
        return FLB_SYSTEMD_BUSY;
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * if there are not pending records from a previous round, likely we got
     * some changes in the journal, otherwise go ahead and continue reading
     * the journal.
     */
    if (ctx->pending_records == FLB_FALSE) {
        ret = sd_journal_process(ctx->j);
        if (ret == SD_JOURNAL_INVALIDATE) {
            flb_plg_debug(ctx->ins,
                          "received event on added or removed journal file");
        }
        if (ret != SD_JOURNAL_APPEND && ret != SD_JOURNAL_NOP) {
            return FLB_SYSTEMD_NONE;
        }
    }

    while ((ret_j = sd_journal_next(ctx->j)) > 0) {
        /* If the tag is composed dynamically, gather the Systemd Unit name */
        if (ctx->dynamic_tag) {
            ret = sd_journal_get_data(ctx->j, "_SYSTEMD_UNIT", &data, &length);
            if (ret == 0) {
                tag = new_tag;
                tag_compose(ctx->ins->tag, (const char *) data + 14, length - 14,
                            &tag, &tag_len);
            }
            else {
                tag = new_tag;
                tag_compose(ctx->ins->tag,
                            FLB_SYSTEMD_UNKNOWN, sizeof(FLB_SYSTEMD_UNKNOWN) - 1,
                            &tag, &tag_len);
            }
        }
        else {
            tag = ctx->ins->tag;
            tag_len = ctx->ins->tag_len;
        }

        if (last_tag_len == 0) {
            strncpy(last_tag, tag, tag_len);
            last_tag_len = tag_len;
        }

        /* Set time */
        ret = sd_journal_get_realtime_usec(ctx->j, &usec);
        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "error reading from systemd journal. "
                          "sd_journal_get_realtime_usec() return value '%i'",
                          ret);
            /* It seems the journal file was deleted (rotated). */
            ret_j = -1;
            break;
        }
        sec = usec / 1000000;
        nsec = (usec % 1000000) * 1000;
        flb_time_set(&tm, sec, nsec);

        /*
         * The new incoming record can have a different tag than previous one,
         * so a new msgpack buffer is required. We ingest the data and prepare
         * a new buffer.
         */
        if (mp_sbuf.size > 0 &&
            ((last_tag_len != tag_len) || (strncmp(last_tag, tag, tag_len) != 0))) {
            flb_input_chunk_append_raw(ctx->ins,
                                       last_tag, last_tag_len,
                                       mp_sbuf.data,
                                       mp_sbuf.size);
            msgpack_sbuffer_destroy(&mp_sbuf);
            msgpack_sbuffer_init(&mp_sbuf);

            strncpy(last_tag, tag, tag_len);
            last_tag_len = tag_len;
        }

        /* Prepare buffer and write map content */
        msgpack_pack_array(&mp_pck, 2);
        flb_time_append_to_msgpack(&tm, &mp_pck, 0);

        /*
         * Save the current size/position of the buffer since this is
         * where the Map header will be stored.
         */
        off = mp_sbuf.size;

        /*
         * Register the maximum fields allowed per entry in the map. With
         * this approach we can ingest all the fields and then just adjust
         * the map size if required.
         */
        msgpack_pack_map(&mp_pck, ctx->max_fields);

        /* Pack every field in the entry */
        entries = 0;
        while (sd_journal_enumerate_data(ctx->j, &data, &length) > 0 &&
               entries < ctx->max_fields) {
            key = (const char *) data;
            if (ctx->strip_underscores == FLB_TRUE && key[0] == '_') {
                key++;
                length--;
            }
            sep = strchr(key, '=');
            len = (sep - key);
            msgpack_pack_str(&mp_pck, len);
            msgpack_pack_str_body(&mp_pck, key, len);

            val = sep + 1;
            len = length - (sep - key) - 1;
            msgpack_pack_str(&mp_pck, len);
            msgpack_pack_str_body(&mp_pck, val, len);

            entries++;
        }
        rows++;
        if (entries == ctx->max_fields) {
            flb_plg_debug(ctx->ins,
                          "max number of fields is reached: %i; all other "
                          "fields are discarded", ctx->max_fields);
        }

        /*
         * The fields were packed, now we need to adjust the msgpack map size
         * to set the proper number of fields appended to the record.
         */
        tmp = mp_sbuf.data + off;
        h = tmp[0];
        if (h >> 4 == 0x8) {
            *tmp = (uint8_t) 0x8 << 4 | ((uint8_t) entries);
        }
        else if (h == 0xde) {
            tmp++;
            pack_uint16(tmp, entries);
        }
        else if (h == 0xdf) {
            tmp++;
            pack_uint32(tmp, entries);
        }

        /*
         * Some journals can have too much data, pause if we have processed
         * more than 1MB. Journal will resume later.
         */
        if (mp_sbuf.size > 1024000) {
            flb_input_chunk_append_raw(ctx->ins,
                                       tag, tag_len,
                                       mp_sbuf.data,
                                       mp_sbuf.size);
            msgpack_sbuffer_destroy(&mp_sbuf);
            msgpack_sbuffer_init(&mp_sbuf);
            strncpy(last_tag, tag, tag_len);
            last_tag_len = tag_len;
            break;
        }

        if (rows >= ctx->max_entries) {
            break;
        }
    }

#ifdef FLB_HAVE_SQLDB
    /* Save cursor */
    if (ctx->db) {
        sd_journal_get_cursor(ctx->j, &cursor);
        if (cursor) {
            flb_systemd_db_set_cursor(ctx, cursor);
            flb_free(cursor);
        }
    }
#endif

    /* Write any pending data into the buffer */
    if (mp_sbuf.size > 0) {
        flb_input_chunk_append_raw(ctx->ins,
                                   tag, tag_len,
                                   mp_sbuf.data,
                                   mp_sbuf.size);
    }
    msgpack_sbuffer_destroy(&mp_sbuf);

    /* the journal is empty, no more records */
    if (ret_j == 0) {
        ctx->pending_records = FLB_FALSE;
        return FLB_SYSTEMD_OK;
    }
    else if (ret_j > 0) {
        /*
        * ret_j == 1, but the loop was broken due to some special condition like
        * buffer size limit or it reach the max number of rows that it supposed to
        * process on this call. Assume there are pending records.
        */
        ctx->pending_records = FLB_TRUE;
        return FLB_SYSTEMD_MORE;
    }
    else {
        /* Supposedly, current cursor points to a deleted file.
         * Re-seeking to the first journal entry.
         * Other failures, such as disk read error, would still lead to infinite loop there,
         * but at least FLB log will be full of errors. */
        ret = sd_journal_seek_head(ctx->j);
        flb_plg_error(ctx->ins,
                      "sd_journal_next() returned error %i; "
                      "journal is re-opened, unread logs are lost; "
                      "sd_journal_seek_head() returned %i", ret_j, ret);
        ctx->pending_records = FLB_TRUE;
        return FLB_SYSTEMD_ERROR;
    }
}

static int in_systemd_collect_archive(struct flb_input_instance *ins,
                                      struct flb_config *config, void *in_context)
{
    int ret;
    uint64_t val;
    ssize_t bytes;
    struct flb_systemd_config *ctx = in_context;

    bytes = read(ctx->ch_manager[0], &val, sizeof(uint64_t));
    if (bytes == -1) {
        flb_errno();
        return -1;
    }

    ret = in_systemd_collect(ins, config, in_context);
    if (ret == FLB_SYSTEMD_OK) {
        /* Events collector: journald events */
        ret = flb_input_set_collector_event(ins,
                                            in_systemd_collect,
                                            ctx->fd,
                                            config);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error setting up collector events");
            flb_systemd_config_destroy(ctx);
            return -1;
        }
        ctx->coll_fd_journal = ret;
        flb_input_collector_start(ctx->coll_fd_journal, ins);

        /* Timer to collect pending events */
        ret = flb_input_set_collector_time(ins,
                                           in_systemd_collect,
                                           1, 0,
                                           config);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "error setting up collector for pending events");
            flb_systemd_config_destroy(ctx);
            return -1;
        }
        ctx->coll_fd_pending = ret;
        flb_input_collector_start(ctx->coll_fd_pending, ins);

        return 0;
    }

    /* If FLB_SYSTEMD_NONE or FLB_SYSTEMD_MORE, keep trying */
    write(ctx->ch_manager[1], &val, sizeof(uint64_t));

    return 0;
}

static int in_systemd_init(struct flb_input_instance *ins,
                           struct flb_config *config, void *data)
{
    int ret;
    struct flb_systemd_config *ctx;

    ctx = flb_systemd_config_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize");
        return -1;
    }

    /* Set the context */
    flb_input_set_context(ins, ctx);

    /* Events collector: archive */
    ret = flb_input_set_collector_event(ins, in_systemd_collect_archive,
                                        ctx->ch_manager[0], config);
    if (ret == -1) {
        flb_systemd_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_archive = ret;

    return 0;
}

static int in_systemd_pre_run(struct flb_input_instance *ins,
                              struct flb_config *config, void *in_context)
{
    int n;
    uint64_t val = 0xc002;
    struct flb_systemd_config *ctx = in_context;
    (void) ins;
    (void) config;

    /* Insert a dummy event into the channel manager */
    n = write(ctx->ch_manager[1], &val, sizeof(val));
    if (n == -1) {
        flb_errno();
        return -1;
    }

    return n;
}

static void in_systemd_pause(void *data, struct flb_config *config)
{
    int ret;
    struct flb_systemd_config *ctx = data;

    flb_input_collector_pause(ctx->coll_fd_archive, ctx->ins);

    /* pause only if it's running */
    ret = flb_input_collector_running(ctx->coll_fd_journal, ctx->ins);
    if (ret == FLB_TRUE) {
        flb_input_collector_pause(ctx->coll_fd_journal, ctx->ins);
        flb_input_collector_pause(ctx->coll_fd_pending, ctx->ins);
    }
}

static void in_systemd_resume(void *data, struct flb_config *config)
{
    int ret;
    struct flb_systemd_config *ctx = data;

    flb_input_collector_resume(ctx->coll_fd_archive, ctx->ins);

    /* resume only if is not running */
    ret = flb_input_collector_running(ctx->coll_fd_journal, ctx->ins);
    if (ret == FLB_FALSE) {
        flb_input_collector_resume(ctx->coll_fd_journal, ctx->ins);
        flb_input_collector_resume(ctx->coll_fd_pending, ctx->ins);
    }
}

static int in_systemd_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_systemd_config *ctx = data;

    flb_systemd_config_destroy(ctx);
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_systemd_plugin = {
    .name         = "systemd",
    .description  = "Systemd (Journal) reader",
    .cb_init      = in_systemd_init,
    .cb_pre_run   = in_systemd_pre_run,
    .cb_flush_buf = NULL,
    .cb_pause     = in_systemd_pause,
    .cb_resume    = in_systemd_resume,
    .cb_exit      = in_systemd_exit,
    .flags        = 0
};
