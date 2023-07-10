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
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_time.h>

#include "systemd_config.h"
#include "systemd_db.h"

#include <ctype.h>

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
    int i;
    int len;
    int entries = 0;
    int skip_entries = 0;
    int rows = 0;
    time_t sec;
    long nsec;
    uint64_t usec;
    size_t length;
    size_t threshold;
    const char *sep;
    const char *key;
    const char *val;
    char *buf = NULL;
#ifdef FLB_HAVE_SQLDB
    char *cursor = NULL;
#endif
    char *tag = NULL;
    char new_tag[PATH_MAX];
    char last_tag[PATH_MAX];
    size_t tag_len;
    size_t last_tag_len = 0;
    const void *data;
    struct flb_systemd_config *ctx = in_context;
    struct flb_time tm;

    /* Restricted by mem_buf_limit */
    if (flb_input_buf_paused(ins) == FLB_TRUE) {
        return FLB_SYSTEMD_BUSY;
    }

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

    if (ctx->lowercase == FLB_TRUE) {
        ret = sd_journal_get_data_threshold(ctx->j, &threshold);
        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "error setting up systemd data. "
                          "sd_journal_get_data_threshold() return value '%i'",
                          ret);
            return FLB_SYSTEMD_ERROR;
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
        if (ctx->log_encoder->output_length > 0 &&
            ((last_tag_len != tag_len) ||
             (strncmp(last_tag, tag, tag_len) != 0))) {
            flb_input_log_append(ctx->ins,
                                 last_tag, last_tag_len,
                                 ctx->log_encoder->output_buffer,
                                 ctx->log_encoder->output_length);

            flb_log_event_encoder_reset(ctx->log_encoder);

            strncpy(last_tag, tag, tag_len);
            last_tag_len = tag_len;
        }


        ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_timestamp(ctx->log_encoder, &tm);
        }

        /* Pack every field in the entry */
        entries = 0;
        skip_entries = 0;
        while (sd_journal_enumerate_data(ctx->j, &data, &length) > 0 &&
               entries < ctx->max_fields) {
            key = (const char *) data;
            if (ctx->strip_underscores == FLB_TRUE && key[0] == '_') {
                key++;
                length--;
            }

            sep = strchr(key, '=');
            if (sep == NULL) {
                skip_entries++;
                continue;
            }

            len = (sep - key);

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_string_length(
                        ctx->log_encoder, len);
            }

            if (ctx->lowercase == FLB_TRUE) {
                /*
                 * Ensure buf to have enough space for the key because the libsystemd
                 * might return larger data than the threshold.
                 */
                if (buf == NULL) {
                    buf = flb_sds_create_len(NULL, threshold);
                }
                if (flb_sds_alloc(buf) < len) {
                    buf = flb_sds_increase(buf, len - flb_sds_alloc(buf));
                }
                for (i = 0; i < len; i++) {
                    buf[i] = tolower(key[i]);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_append_body_string_body(
                            ctx->log_encoder, buf, len);
                }
            }
            else {
                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_append_body_string_body(
                            ctx->log_encoder, (char *) key, len);
                }
            }

            val = sep + 1;
            len = length - (sep - key) - 1;

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_string(
                        ctx->log_encoder, (char *) val, len);
            }

            entries++;
        }
        rows++;

        if (skip_entries > 0) {
            flb_plg_error(ctx->ins, "Skip %d broken entries", skip_entries);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
        }

        /*
         * Some journals can have too much data, pause if we have processed
         * more than 1MB. Journal will resume later.
         */
        if (ctx->log_encoder->output_length > 1024000) {
            flb_input_log_append(ctx->ins,
                                 tag, tag_len,
                                 ctx->log_encoder->output_buffer,
                                 ctx->log_encoder->output_length);

            flb_log_event_encoder_reset(ctx->log_encoder);

            strncpy(last_tag, tag, tag_len);
            last_tag_len = tag_len;

            break;
        }

        if (rows >= ctx->max_entries) {
            break;
        }
    }

    flb_sds_destroy(buf);

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
    if (ctx->log_encoder->output_length > 0) {
        flb_input_log_append(ctx->ins,
                             tag, tag_len,
                             ctx->log_encoder->output_buffer,
                             ctx->log_encoder->output_length);

        flb_log_event_encoder_reset(ctx->log_encoder);
    }

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

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_STR, "path", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_systemd_config, path),
      "Set the systemd journal path"
    },
    {
      FLB_CONFIG_MAP_INT, "max_fields", FLB_SYSTEMD_MAX_FIELDS,
      0, FLB_TRUE, offsetof(struct flb_systemd_config, max_fields),
      "Set the maximum fields per notification"
    },
    {
      FLB_CONFIG_MAP_INT, "max_entries", FLB_SYSTEMD_MAX_ENTRIES,
      0, FLB_TRUE, offsetof(struct flb_systemd_config, max_entries),
      "Set the maximum entries per notification"
    },
    {
      FLB_CONFIG_MAP_STR, "systemd_filter_type", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_systemd_config, filter_type),
      "Set the systemd filter type to either 'and' or 'or'"
    },
    {
      FLB_CONFIG_MAP_STR, "systemd_filter", (char *)NULL,
      FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_systemd_config, systemd_filters),
      "Add a systemd filter, can be set multiple times"
    },
    {
      FLB_CONFIG_MAP_BOOL, "read_from_tail", "false",
      0, FLB_TRUE, offsetof(struct flb_systemd_config, read_from_tail),
      "Read the journal from the end (tail)"
    },
    {
      FLB_CONFIG_MAP_BOOL, "lowercase", "false",
      0, FLB_TRUE, offsetof(struct flb_systemd_config, lowercase),
      "Lowercase the fields"
    },
    {
      FLB_CONFIG_MAP_BOOL, "strip_underscores", "false",
      0, FLB_TRUE, offsetof(struct flb_systemd_config, strip_underscores),
      "Strip undersecores from fields"
    },
#ifdef FLB_HAVE_SQLDB
    {
      FLB_CONFIG_MAP_STR, "db.sync", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_systemd_config, db_sync_mode),
      "Set the database sync mode: extra, full, normal or off"
    },
    {
      FLB_CONFIG_MAP_STR, "db", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_systemd_config, db_path),
      "Set the database path"
    },
#endif /* FLB_HAVE_SQLDB */
    /* EOF */
    {0}
};

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
    .config_map   = config_map,
    .flags        = 0
};
