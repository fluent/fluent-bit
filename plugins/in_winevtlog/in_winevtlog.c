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
#include <fluent-bit/flb_kernel.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sqldb.h>
#include "winevtlog.h"

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0
#define DEFAULT_THRESHOLD_SIZE 0x7ffff /* Default reading buffer size */
                                       /* (512kib = 524287bytes) */
#define MINIMUM_THRESHOLD_SIZE 0x0400   /* 1024 bytes */
#define MAXIMUM_THRESHOLD_SIZE (FLB_INPUT_CHUNK_FS_MAX_SIZE - (1024 * 200))

static int in_winevtlog_collect(struct flb_input_instance *ins,
                                struct flb_config *config, void *in_context);

static wchar_t* convert_to_wide(struct winevtlog_config *ctx, char *str)
{
    int size = 0;
    wchar_t *buf = NULL;
    DWORD err;

    size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (size == 0) {
        err = GetLastError();
        flb_plg_error(ctx->ins, "Failed MultiByteToWideChar with error code (%d)", err);
        return NULL;
    }

    buf = flb_calloc(1, sizeof(wchar_t) * size);
    if (buf == NULL) {
        flb_errno();
        return NULL;
    }
    size = MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, size);
    if (size == 0) {
        err = GetLastError();
        flb_plg_error(ctx->ins, "Failed MultiByteToWideChar with error code (%d)", err);
        flb_free(buf);
        return NULL;
    }

    return buf;
}

static void in_winevtlog_session_destroy(struct winevtlog_session *session);

static struct winevtlog_session *in_winevtlog_session_create(struct winevtlog_config *ctx,
                                                             struct flb_config *config,
                                                             int *status)
{
    int len;
    struct winevtlog_session *session;
    PWSTR wtmp;

    if (ctx->remote_server == NULL) {
        *status = WINEVTLOG_SESSION_SERVER_EMPTY;
        return NULL;
    }

    session = flb_calloc(1, sizeof(struct winevtlog_session));
    if (session == NULL) {
        flb_errno();
        *status = WINEVTLOG_SESSION_ALLOC_FAILED;
        return NULL;
    }

    if (ctx->remote_server != NULL) {
        session->server = convert_to_wide(ctx, ctx->remote_server);
        if (session->server == NULL) {
            in_winevtlog_session_destroy(session);
            *status = WINEVTLOG_SESSION_FAILED_TO_CONVERT_WIDE;
            return NULL;
        }
    }

    if (ctx->remote_domain != NULL) {
        session->domain = convert_to_wide(ctx, ctx->remote_domain);
        if (session->domain == NULL) {
            in_winevtlog_session_destroy(session);
            *status = WINEVTLOG_SESSION_FAILED_TO_CONVERT_WIDE;
            return NULL;
        }
    }

    if (ctx->remote_username != NULL) {
        session->username = convert_to_wide(ctx, ctx->remote_username);
        if (session->username == NULL) {
            in_winevtlog_session_destroy(session);
            *status = WINEVTLOG_SESSION_FAILED_TO_CONVERT_WIDE;
            return NULL;
        }
    }

    if (ctx->remote_password != NULL) {
        session->password = convert_to_wide(ctx, ctx->remote_password);
        if (session->password == NULL) {
            in_winevtlog_session_destroy(session);
            *status = WINEVTLOG_SESSION_FAILED_TO_CONVERT_WIDE;
            return NULL;
        }
    }

    session->flags = EvtRpcLoginAuthDefault;
    *status = WINEVTLOG_SESSION_CREATE_OK;

    return session;
}

static void in_winevtlog_session_destroy(struct winevtlog_session *session)
{
    if (session->server != NULL) {
        flb_free(session->server);
    }

    if (session->domain != NULL) {
        flb_free(session->domain);
    }

    if (session->username != NULL) {
        flb_free(session->username);
    }

    if (session->password != NULL) {
        flb_free(session->password);
    }

    flb_free(session);
}

static int in_winevtlog_init(struct flb_input_instance *in,
                             struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    char human_readable_size[32];
    int read_existing_events = FLB_FALSE;
    struct mk_list *head;
    struct winevtlog_channel *ch;
    struct winevtlog_config *ctx;
    struct winevtlog_session *session;
    int status = WINEVTLOG_SESSION_CREATE_OK;
    double mult = 2.0;
    DWORD tmp_ms = 0;

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

        return -1;
    }

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    /* Rendering options are mutually exclusive */
    if (ctx->render_event_as_xml && ctx->render_event_as_text) {
        flb_plg_error(in,
                      "render_event_as_xml and render_event_as_text cannot be enabled at the same time");
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    if (ctx->render_event_as_text) {
        if (ctx->render_event_text_key == NULL || ctx->render_event_text_key[0] == '\0') {
            flb_plg_error(in, "render_event_text_key cannot be empty when render_event_as_text is enabled");
            flb_log_event_encoder_destroy(ctx->log_encoder);
            flb_free(ctx);
            return -1;
        }
    }

    if (ctx->backoff_multiplier_str && ctx->backoff_multiplier_str[0] != '\0') {
        mult = atof(ctx->backoff_multiplier_str);
        if (mult <= 0.0) {
            flb_plg_warn(in, "invalid reconnect.multiplier='%s', fallback to 2.0",
                         ctx->backoff_multiplier_str);
            mult = 2.0;
        }
    }
    ctx->backoff.multiplier_x1000 = (DWORD)(mult * 1000.0);

    /* normalize base/max/jitter/retries to sane ranges */
    if (ctx->backoff.base_ms <= 0) {
        ctx->backoff.base_ms = 500;
    }
    if (ctx->backoff.max_ms  <= 0) {
        ctx->backoff.max_ms  = 30000;
    }
    if (ctx->backoff.jitter_pct < 0) {
        ctx->backoff.jitter_pct = 0;
    }
    if (ctx->backoff.max_retries < 0) {
        ctx->backoff.max_retries = 0;
    }

    /* clamp out-of-range values, protecting against negative INT written into DWORD */
    if (ctx->backoff.base_ms > 3600000U) { /* cap at 1 hour */
        ctx->backoff.base_ms = 3600000U;
    }
    if (ctx->backoff.max_ms > 86400000U) { /* cap at 24 hours */
        ctx->backoff.max_ms = 86400000U;
    }
    if (ctx->backoff.jitter_pct > 100U) {  /* jitter as percentage */
        ctx->backoff.jitter_pct = 100U;
    }
    if ((unsigned) ctx->backoff.max_retries > 100U) { /* cap retries */
        ctx->backoff.max_retries = 100;
    }
    /* ensure ordering */
    if (ctx->backoff.max_ms < ctx->backoff.base_ms) {
        flb_plg_warn(in, "reconnect.max_ms < reconnect.base_ms, swapping values");
        tmp_ms = ctx->backoff.base_ms;
        ctx->backoff.base_ms = ctx->backoff.max_ms;
        ctx->backoff.max_ms  = tmp_ms;
    }

    if (ctx->backoff.multiplier_x1000 < 500)  {
        ctx->backoff.multiplier_x1000 = 500;
    }

    if (ctx->backoff.multiplier_x1000 > 10000) {
        ctx->backoff.multiplier_x1000 = 10000;
    }

    /* Initialize session context */
    session = in_winevtlog_session_create(ctx, config, &status);
    if (status == WINEVTLOG_SESSION_ALLOC_FAILED ||
        status == WINEVTLOG_SESSION_FAILED_TO_CONVERT_WIDE) {
        flb_plg_error(in, "session is not created and invalid with status %d", status);
        return -1;
    }
    else if (session == NULL) {
        flb_plg_debug(in, "connect to local machine");
    }
    ctx->session = session;

    /* Set up total reading size threshold */
    if (ctx->total_size_threshold >= MINIMUM_THRESHOLD_SIZE &&
        ctx->total_size_threshold <= MAXIMUM_THRESHOLD_SIZE) {
        flb_utils_bytes_to_human_readable_size((size_t) ctx->total_size_threshold,
                                               human_readable_size,
                                               sizeof(human_readable_size) - 1);
        flb_plg_debug(ctx->ins,
                      "read limit per cycle is set up as %s",
                      human_readable_size);
    }
    else if (ctx->total_size_threshold > MAXIMUM_THRESHOLD_SIZE) {
        flb_utils_bytes_to_human_readable_size((size_t) MAXIMUM_THRESHOLD_SIZE,
                                               human_readable_size,
                                               sizeof(human_readable_size) - 1);
        flb_plg_warn(ctx->ins,
                     "read limit per cycle cannot exceed %s. Set up to %s",
                     human_readable_size, human_readable_size);
        ctx->total_size_threshold = (unsigned int) MAXIMUM_THRESHOLD_SIZE;
    }
    else if (ctx->total_size_threshold < MINIMUM_THRESHOLD_SIZE){
        flb_utils_bytes_to_human_readable_size((size_t) MINIMUM_THRESHOLD_SIZE,
                                               human_readable_size,
                                               sizeof(human_readable_size) - 1);
        flb_plg_warn(ctx->ins,
                     "read limit per cycle cannot under 1KiB. Set up to %s",
                     human_readable_size);
        ctx->total_size_threshold = (unsigned int) MINIMUM_THRESHOLD_SIZE;
    }

    /* Open channels */
    tmp = flb_input_get_property("channels", in);
    if (!tmp) {
        flb_plg_debug(ctx->ins, "no channel provided. listening to 'Application'");
        tmp = "Application";
    }

    ctx->active_channel = winevtlog_open_all(tmp, ctx);
    if (!ctx->active_channel) {
        if (ctx->ignore_missing_channels) {
            flb_plg_debug(ctx->ins, "failed to open and no subscribed channels");
        }
        else {
            flb_plg_error(ctx->ins, "failed to open and no subscribed channels. Subscribe at least one");
            flb_log_event_encoder_destroy(ctx->log_encoder);
            flb_free(ctx);
            return -1;
        }
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
            winevtlog_sqlite_load(ch, ctx, ctx->db);
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
        winevtlog_sqlite_save(ch, ctx, ctx->db);
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

    /* If there are no active channels (e.g., all missing and ignored),
     * there is nothing to collect. Guard against NULL to avoid dereferencing.
     */
    if (ctx == NULL || ctx->active_channel == NULL) {
        return 0;
    }

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

    if (ctx->active_channel) {
        winevtlog_close_all(ctx->active_channel);
    }

    if (ctx->db) {
        flb_sqldb_close(ctx->db);
    }
    if (ctx->session) {
        in_winevtlog_session_destroy(ctx->session);
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
      "Render Windows EventLog as XML (System and Message fields)"
    },
    {
      FLB_CONFIG_MAP_BOOL, "render_event_as_text", "false",
      0, FLB_TRUE, offsetof(struct winevtlog_config, render_event_as_text),
      "Render Windows EventLog as newline-separated key=value text"
    },
    {
      FLB_CONFIG_MAP_STR, "render_event_text_key", "log",
      0, FLB_TRUE, offsetof(struct winevtlog_config, render_event_text_key),
      "Record key name used when render_event_as_text is enabled"
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
    {
      FLB_CONFIG_MAP_STR, "event_query", "*",
      0, FLB_TRUE, offsetof(struct winevtlog_config, event_query),
      "Specify XML query for filtering events"
    },
    {
      FLB_CONFIG_MAP_SIZE, "read_limit_per_cycle", "524287",
      0, FLB_TRUE, offsetof(struct winevtlog_config, total_size_threshold),
      "Specify reading limit for collecting Windows EventLog per a cycle"
    },
    {
      FLB_CONFIG_MAP_STR, "remote.server", (char *)NULL,
      0, FLB_TRUE, offsetof(struct winevtlog_config, remote_server),
      "Specify server name of remote access for Windows EventLog"
    },
    {
      FLB_CONFIG_MAP_STR, "remote.domain", (char *)NULL,
      0, FLB_TRUE, offsetof(struct winevtlog_config, remote_domain),
      "Specify domain name of remote access for Windows EventLog"
    },
    {
      FLB_CONFIG_MAP_STR, "remote.username", (char *)NULL,
      0, FLB_TRUE, offsetof(struct winevtlog_config, remote_username),
      "Specify username of remote access for Windows EventLog"
    },
    {
      FLB_CONFIG_MAP_STR, "remote.password", (char *)NULL,
      0, FLB_TRUE, offsetof(struct winevtlog_config, remote_password),
      "Specify password of remote access for Windows EventLog"
    },
    /* ---- reconnect backoff parameters ---- */
    {
      FLB_CONFIG_MAP_INT, "reconnect.base_ms", "500",
      0, FLB_TRUE, offsetof(struct winevtlog_config, backoff.base_ms),
      "Initial reconnect backoff in milliseconds"
    },
    {
      FLB_CONFIG_MAP_INT, "reconnect.max_ms", "30000",
      0, FLB_TRUE, offsetof(struct winevtlog_config, backoff.max_ms),
      "Maximum reconnect backoff in milliseconds"
    },
    {
      FLB_CONFIG_MAP_STR, "reconnect.multiplier", "2.0",
      0, FLB_TRUE, offsetof(struct winevtlog_config, backoff_multiplier_str),
      "Exponential backoff multiplier (float, e.g. 2.0)"
    },
    {
      FLB_CONFIG_MAP_INT, "reconnect.jitter_pct", "20",
      0, FLB_TRUE, offsetof(struct winevtlog_config, backoff.jitter_pct),
      "Jitter percentage applied to backoff (e.g. 20 means ±20%)"
    },
    {
      FLB_CONFIG_MAP_INT, "reconnect.max_retries", "8",
      0, FLB_TRUE, offsetof(struct winevtlog_config, backoff.max_retries),
      "Max reconnect attempts before giving up"
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
