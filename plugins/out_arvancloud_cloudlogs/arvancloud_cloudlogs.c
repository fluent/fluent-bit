/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_strptime.h>
#include <fluent-bit/flb_parser.h>
#include <time.h>
#include <stdio.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include "arvancloud_cloudlogs.h"

/*
 * Format timestamp to RFC3339 string with microseconds
 * Returns the length of the formatted string
 */
static size_t format_timestamp_rfc3339(char *buffer, size_t buffer_size,
                                        time_t seconds, long nsec)
{
    struct tm tm;
    size_t s;
    int len;
    
    gmtime_r(&seconds, &tm);
    s = strftime(buffer, buffer_size - 1, "%Y-%m-%dT%H:%M:%S", &tm);
    len = snprintf(buffer + s, buffer_size - 1 - s,
                   ".%06ldZ", (long) (nsec / 1000));
    return s + len;
}

/*
 * Parse timestamp string using flb_strptime format or auto-detect ISO8601
 * Returns 0 on success, -1 on failure
 * Extracts fractional seconds separately if present
 */
static int parse_timestamp_string(const char *timestamp_str,
                                   const char *format,
                                   struct flb_tm *tm_out,
                                   long *nsec_out)
{
    char *result;
    const char *frac_ptr;
    long frac_value;
    int digit_count;

    frac_value = 0;
    digit_count = 0;

    if (!timestamp_str || !tm_out || !nsec_out) {
        return -1;
    }

    memset(tm_out, 0, sizeof(struct flb_tm));
    tm_out->tm.tm_isdst = -1;
    flb_tm_gmtoff(tm_out) = 0;
    *nsec_out = 0;

    /* Use flb_strptime with provided format or try auto-detection */
    if (format && format[0] != '\0') {
        /* User-provided format */
        result = flb_strptime(timestamp_str, format, tm_out);
        if (!result) {
            return -1;
        }
    }
    else {
        /* Auto-detect ISO8601 format - try common patterns */
        /* First try with timezone: 2025-09-29T12:33:20+03:30 */
        result = flb_strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S%z", tm_out);
        
        if (!result) {
            /* Try UTC format: 2025-09-29T12:33:20Z */
            result = flb_strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ", tm_out);
        }
        
        if (!result) {
            /* Try without timezone: 2025-09-29T12:33:20 */
            result = flb_strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S", tm_out);
        }
        
        if (!result) {
            return -1;
        }
    }

    /* Extract fractional seconds if present (flb_strptime doesn't handle them) */
    frac_ptr = strchr(timestamp_str, '.');
    if (frac_ptr) {
        frac_ptr++; /* Skip the dot */
        
        /* Count digits and parse fractional part */
        while (*frac_ptr >= '0' && *frac_ptr <= '9' && digit_count < 9) {
            frac_value = frac_value * 10 + (*frac_ptr - '0');
            digit_count++;
            frac_ptr++;
        }
        
        /* Convert to nanoseconds based on precision */
        if (digit_count > 0) {
            /* Scale up to nanoseconds */
            while (digit_count < 9) {
                frac_value *= 10;
                digit_count++;
            }
            *nsec_out = frac_value;
        }
    }

    return 0;
}

static int arvancloud_format(struct flb_config *config,
                        struct flb_input_instance *ins,
                        void *plugin_context,
                        void *flush_context,
                        int event_type,
                        const char *tag, int tag_len,
                        const void *data, size_t bytes,
                        void **out_data, size_t *out_size)
{
    int ret;
    size_t final_log_type_len;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct flb_out_arvancloud_cloudlogs *ctx;
    struct flb_event_chunk *event_chunk;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    size_t count;
    size_t s;
    struct flb_time t;
    char time_formatted[64];
    flb_sds_t log_type_value;
    const char *final_log_type;

    ctx = plugin_context;
    event_chunk = flush_context;
    count = 0;

    (void) ins;
    (void) event_type;

    /* Get event count from event_chunk if available, otherwise count manually */
    if (event_chunk != NULL) {
        count = event_chunk->total_events;
    }
    else {
        count = flb_mp_count(data, bytes);
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "log event decoder init error: %d", ret);
        return -1;
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Build request object: { allowPartialProcess: bool, logs: [ ... ] } */
    msgpack_pack_map(&mp_pck, 2);

    /* allowPartialProcess */
    msgpack_pack_str(&mp_pck, 19);
    msgpack_pack_str_body(&mp_pck, "allowPartialProcess", 19);
    if (ctx->allow_partial_process) {
        msgpack_pack_true(&mp_pck);
    }
    else {
        msgpack_pack_false(&mp_pck);
    }

    /* logs */
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "logs", 4);

    msgpack_pack_array(&mp_pck, count);

    while ((ret = flb_log_event_decoder_next(
                &log_decoder, &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        t = log_event.timestamp;
        log_type_value = NULL;

        msgpack_pack_map(&mp_pck, ctx->include_tag_key ? 6 : 5);

        /* logType: priority order is log_type_key > log_type */
        if (ctx->log_type_key && ctx->ra_log_type_key) {
            /* Try to extract from record using log_type_key */
            log_type_value = flb_ra_translate(ctx->ra_log_type_key,
                                              tag, tag_len,
                                              *log_event.body, NULL);
            if (log_type_value && !flb_sds_is_empty(log_type_value)) {
                final_log_type = log_type_value;
                final_log_type_len = flb_sds_len(log_type_value);
            }
            else {
                /* Clean up failed extraction and fall back to log_type */
                if (log_type_value) {
                    flb_sds_destroy(log_type_value);
                    log_type_value = NULL;
                }
                final_log_type = ctx->log_type;
                final_log_type_len = flb_sds_len(ctx->log_type);
            }
        }
        else {
            /* Use configured log_type (has default value) */
            final_log_type = ctx->log_type;
            final_log_type_len = flb_sds_len(ctx->log_type);
        }

        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "logType", 7);
        msgpack_pack_str(&mp_pck, final_log_type_len);
        msgpack_pack_str_body(&mp_pck, final_log_type, final_log_type_len);

        /* Clean up if we allocated log_type_value */
        if (log_type_value) {
            flb_sds_destroy(log_type_value);
        }

        /* timestamp: Try to extract from record if timestamp_key is configured */
        if (ctx->timestamp_key && ctx->ra_timestamp_key) {
            flb_sds_t timestamp_value;
            struct flb_tm parsed_tm;
            long parsed_nsec;
            time_t parsed_time;
            int parse_success;
            const char *fmt;
            long gmtoff_value;
            time_t time_before_adjustment;

            parsed_nsec = 0;
            parse_success = 0;
            
            /* Try to extract timestamp from record */
            timestamp_value = flb_ra_translate(ctx->ra_timestamp_key,
                                               tag, tag_len,
                                               *log_event.body, NULL);
            
            if (timestamp_value && !flb_sds_is_empty(timestamp_value)) {
                /* Try to parse the extracted timestamp */
                fmt = ctx->timestamp_format ? ctx->timestamp_format : NULL;
                
                if (parse_timestamp_string(timestamp_value, fmt,
                                          &parsed_tm, &parsed_nsec) == 0) {
                    /*
                     * Successfully parsed, use the extracted timestamp
                     * Convert flb_tm to time_t, accounting for timezone offset
                     * IMPORTANT: Read gmtoff BEFORE calling timegm() as timegm() may modify the struct
                     */
                    gmtoff_value = flb_tm_gmtoff(&parsed_tm);
                    time_before_adjustment = timegm(&parsed_tm.tm);
                    parsed_time = time_before_adjustment - gmtoff_value;
              
                    s = format_timestamp_rfc3339(time_formatted,
                                                 sizeof(time_formatted),
                                                 parsed_time, parsed_nsec);
                    parse_success = 1;
                } else {
                    /* Parse failed, log warning and fall back to event timestamp */
                    flb_plg_warn(ctx->ins, 
                                "Failed to parse timestamp from field '%s': %s, "
                                "falling back to event timestamp",
                                ctx->timestamp_key, timestamp_value);
                }
                
                flb_sds_destroy(timestamp_value);
            }
            
            /* If parsing failed or extraction failed, use event timestamp */
            if (!parse_success) {
                s = format_timestamp_rfc3339(time_formatted,
                                             sizeof(time_formatted),
                                             t.tm.tv_sec, t.tm.tv_nsec);
            }
        }
        else {
            /* timestamp_key not configured, use event timestamp */
            s = format_timestamp_rfc3339(time_formatted, sizeof(time_formatted),
                                         t.tm.tv_sec, t.tm.tv_nsec);
        }

        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "timestamp", 9);
        msgpack_pack_str(&mp_pck, s);
        msgpack_pack_str_body(&mp_pck, time_formatted, s);

        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "severity", 8);
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "INFO", 4);

        /* resource: minimal object */
        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "resource", 8);
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "type", 4);
        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "general", 7);

        /* payload: original record map */
        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "payload", 7);
        msgpack_pack_object(&mp_pck, *log_event.body);

        /* Include tag key within the log object if configured */
        if (ctx->include_tag_key) {
            msgpack_pack_str(&mp_pck, flb_sds_len(ctx->tag_key));
            msgpack_pack_str_body(&mp_pck, ctx->tag_key, flb_sds_len(ctx->tag_key));
            msgpack_pack_str(&mp_pck, tag_len);
            msgpack_pack_str_body(&mp_pck, tag, tag_len);
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);

    *out_data = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                             config->json_escape_unicode);
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (!*out_data) {
        return -1;
    }
    *out_size = flb_sds_len((flb_sds_t) *out_data);
    return 0;
}

static void cb_arvancloud_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    int compressed;
    int ret;
    size_t b_sent;
    size_t payload_size;
    size_t final_payload_size;
    size_t prefix_len;
    void *payload_buf;
    void *final_payload;
    const char *prefix;
    flb_sds_t header;
    struct flb_out_arvancloud_cloudlogs *ctx;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    compressed = FLB_FALSE;
    payload_size = 0;
    final_payload_size = 0;
    payload_buf = NULL;
    final_payload = NULL;
    ctx = out_context;

    (void) out_flush;
    (void) i_ins;

    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    ret = arvancloud_format(config, i_ins, ctx, event_chunk,
                       event_chunk->type,
                       event_chunk->tag, flb_sds_len(event_chunk->tag),
                       event_chunk->data, event_chunk->size,
                       &payload_buf, &payload_size);
    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    final_payload = payload_buf;
    final_payload_size = payload_size;
    if (ctx->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress((void *) payload_buf, payload_size,
                                &final_payload, &final_payload_size);
        if (ret == 0) {
            compressed = FLB_TRUE;
        }
        else {
            flb_plg_error(ctx->ins, "cannot gzip payload, disabling compression");
            final_payload = payload_buf;
            final_payload_size = payload_size;
        }
    }

    /* Debug: dump request JSON payload */
    flb_plg_debug(ctx->ins, "request payload (%zu bytes): %.*s",
                  final_payload_size,
                  (int) final_payload_size,
                  (const char *) final_payload);

    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        final_payload, final_payload_size,
                        NULL, 0,     // host=NULL, port=0 -> use from u_conn
                        NULL, 0);    // proxy=NULL
    if (!c) {
        if (final_payload != payload_buf) {
            flb_free(final_payload);
        }
        flb_sds_destroy((flb_sds_t) payload_buf);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Add standard headers */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    
    /* Content Encoding: gzip */
    if (compressed == FLB_TRUE) {
        flb_http_set_content_encoding_gzip(c);
    }
    
    /* API Key Authorization header: "apikey <api_key>" */
    if (ctx->api_key) {
        prefix = "apikey ";
        prefix_len = 7;
        header = flb_sds_create_size(prefix_len + flb_sds_len(ctx->api_key));
        if (header) {
            header = flb_sds_cat(header, prefix, prefix_len);
            header = flb_sds_cat(header, ctx->api_key,
                                 flb_sds_len(ctx->api_key));
            flb_http_add_header(c, "Authorization", 13, header,
                                flb_sds_len(header));
            flb_sds_destroy(header);
        }
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        ret = FLB_RETRY;
    }
    else {
        /* Handle HTTP status codes */
        if (c->resp.status >= 200 && c->resp.status <= 205) {
            /* Success: 200 OK, 201 Created, 202 Accepted, 203-205 */
            flb_plg_debug(ctx->ins, "HTTP status=%i", c->resp.status);
            if (c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_debug(ctx->ins, "response body (%zu bytes): %.*s",
                              c->resp.payload_size,
                              (int) c->resp.payload_size,
                              (const char *) c->resp.payload);
            }
            ret = FLB_OK;
        }
        else if (c->resp.status == 400) {
            /* Bad Request - usually a client error, don't retry */
            flb_plg_error(ctx->ins, "HTTP status=400 (Bad Request)");
            if (c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "response body: %.*s",
                              (int) c->resp.payload_size,
                              (const char *) c->resp.payload);
            }
            ret = FLB_ERROR;
        }
        else if (c->resp.status == 401 || c->resp.status == 403) {
            /* Unauthorized or Forbidden - auth issue, don't retry */
            flb_plg_error(ctx->ins,
                          "HTTP status=%i (Authentication/Authorization failed)",
                          c->resp.status);
            if (c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "response body: %.*s",
                              (int) c->resp.payload_size,
                              (const char *) c->resp.payload);
            }
            ret = FLB_ERROR;
        }
        else if (c->resp.status == 429) {
            /* Too Many Requests - rate limit, retry */
            flb_plg_warn(ctx->ins,
                         "HTTP status=429 (Rate Limited), will retry");
            ret = FLB_RETRY;
        }
        else if (c->resp.status >= 500) {
            /* Server errors - retry */
            flb_plg_warn(ctx->ins,
                         "HTTP status=%i (Server Error), will retry",
                         c->resp.status);
            if (c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_warn(ctx->ins, "response body: %.*s",
                             (int) c->resp.payload_size,
                             (const char *) c->resp.payload);
            }
            ret = FLB_RETRY;
        }
        else {
            /* Other client errors - don't retry */
            flb_plg_error(ctx->ins, "HTTP status=%i (Client Error)", c->resp.status);
            if (c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "response body: %.*s",
                              (int) c->resp.payload_size,
                              (const char *) c->resp.payload);
            }
            ret = FLB_ERROR;
        }
    }

    if (final_payload != payload_buf) {
        flb_free(final_payload);
    }
    flb_sds_destroy((flb_sds_t) payload_buf);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    FLB_OUTPUT_RETURN(ret);
}

static int cb_arvancloud_init(struct flb_output_instance *ins,
                              struct flb_config *config,
                              void *data)
{
    struct flb_out_arvancloud_cloudlogs *ctx;
    (void) data;

    ctx = flb_arvancloud_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }
    flb_output_set_context(ins, ctx);
    return 0;
}

static int cb_arvancloud_exit(void *data, struct flb_config *config)
{
    (void) config;
    return flb_arvancloud_conf_destroy(data);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "apikey", NULL,
        0, FLB_TRUE, offsetof(struct flb_out_arvancloud_cloudlogs, api_key),
        "API key for authorization (will be sent as 'apikey <value>')"
    },
    {
        FLB_CONFIG_MAP_STR, "log_type", FLB_ARVANCLOUD_LOG_TYPE,
        0, FLB_TRUE, offsetof(struct flb_out_arvancloud_cloudlogs, log_type),
        "Log type value to use. Defaults to 'fluentbit'."
    },
    {
        FLB_CONFIG_MAP_STR, "log_type_key", NULL,
        0, FLB_TRUE, offsetof(struct flb_out_arvancloud_cloudlogs, log_type_key),
        "Field in the record to use as log type. "
        "Takes priority over 'log_type' and tag prefix."
    },
    {
        FLB_CONFIG_MAP_BOOL, "gzip", "false",
        0, FLB_TRUE, offsetof(struct flb_out_arvancloud_cloudlogs, compress_gzip),
        "Enable gzip compression"
    },
    {
        FLB_CONFIG_MAP_BOOL, "allow_partial_process", "false",
        0, FLB_TRUE,
        offsetof(struct flb_out_arvancloud_cloudlogs, allow_partial_process),
        "Allow server partial processing"
    },
    {
        FLB_CONFIG_MAP_BOOL, "include_tag_key", "false",
        0, FLB_TRUE, offsetof(struct flb_out_arvancloud_cloudlogs, include_tag_key),
        "Include original tag in each record"
    },
    {
        FLB_CONFIG_MAP_STR, "tag_key", "tag",
        0, FLB_TRUE, offsetof(struct flb_out_arvancloud_cloudlogs, tag_key),
        "Tag key name when include_tag_key=true"
    },
    {
        FLB_CONFIG_MAP_STR, "timestamp_key", NULL,
        0, FLB_TRUE, offsetof(struct flb_out_arvancloud_cloudlogs, timestamp_key),
        "Field in the record to use as log timestamp. "
        "If not set, uses Fluent Bit event timestamp."
    },
    {
        FLB_CONFIG_MAP_STR, "timestamp_format", NULL,
        0, FLB_TRUE, offsetof(struct flb_out_arvancloud_cloudlogs, timestamp_format),
        "strptime format string to parse timestamp_key. "
        "If not set, tries to auto-detect ISO8601 format. "
        "Example: '%Y-%m-%dT%H:%M:%S%z' for ISO8601 with timezone."
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_arvancloud_cloudlogs_plugin = {
    .name         = "arvancloud_cloudlogs",
    .description  = "Send events to ArvanCloud CloudLogs",
    .cb_init      = cb_arvancloud_init,
    .cb_flush     = cb_arvancloud_flush,
    .cb_exit      = cb_arvancloud_exit,
    .test_formatter.callback = arvancloud_format,
    .config_map   = config_map,
    .flags        = FLB_OUTPUT_NET | FLB_IO_TLS,
};


