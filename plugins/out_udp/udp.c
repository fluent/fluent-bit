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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "udp.h"
#include "udp_conf.h"

static int cb_udp_init(struct flb_output_instance *ins,
                       struct flb_config *config, void *data)
{
    struct flb_out_udp *ctx = NULL;
    (void) data;

    ctx = flb_udp_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static int deliver_chunks_raw(struct flb_out_udp *ctx,
                              const char *tag, int tag_len,
                              const void *in_data, size_t in_size)
{
    int ret;
    flb_sds_t buf = NULL;
    flb_sds_t str;
    msgpack_object map;
    ssize_t send_result;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    buf = flb_sds_create_size(in_size);
    if (!buf) {
        return FLB_ERROR;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) in_data, in_size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        flb_sds_destroy(buf);

        return -1;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map = *log_event.body;

        str = flb_ra_translate(ctx->ra_raw_message_key, (char *) tag, tag_len, map, NULL);
        if (!str) {
            continue;
        }

        ret = flb_sds_cat_safe(&buf, str, flb_sds_len(str));
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to compose payload from '%s'", str);
        }
        flb_sds_destroy(str);

        /* append a new line */
        flb_sds_cat_safe(&buf, "\n", 1);

        if (flb_sds_len(buf) > 65535) {
            flb_plg_debug(ctx->ins, "record size exceeds maximum datagram size : %zu", flb_sds_len(buf));
        }

        send_result = send(ctx->endpoint_descriptor,
                           buf,
                           flb_sds_len(buf),
                           0);

        if (send_result == -1) {
            flb_log_event_decoder_destroy(&log_decoder);
            flb_sds_destroy(buf);

            return FLB_RETRY;
        }

        flb_sds_len_set(buf, 0);
        buf[0] = '\0';
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_sds_destroy(buf);

    return FLB_OK;
}

static int deliver_chunks_json(struct flb_out_udp *ctx,
                               const char *tag, int tag_len,
                               const void *in_data, size_t in_size,
                               struct flb_config *config)
{
    int ret;
    size_t off = 0;
    flb_sds_t json = NULL;
    ssize_t send_result;
    size_t previous_offset;
    int append_new_line;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) in_data, in_size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_ERROR;
    }

    previous_offset = 0;

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        off = log_decoder.offset;

        json = flb_pack_msgpack_to_json_format(&((char *) in_data)[previous_offset],
                                               off - previous_offset,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->date_key,
                                               config->json_escape_unicode);
        if (!json) {
            flb_plg_error(ctx->ins, "error formatting JSON payload");

            flb_log_event_decoder_destroy(&log_decoder);

            return FLB_ERROR;
        }

        previous_offset = off;
        append_new_line = FLB_FALSE;

        if (flb_sds_len(json) > 0) {
            if (json[flb_sds_len(json) - 1] != '\n') {
                append_new_line = FLB_TRUE;
            }

            if (append_new_line) {
                ret = flb_sds_cat_safe(&json, "\n", 1);

                if (ret != 0) {
                    flb_log_event_decoder_destroy(&log_decoder);
                    flb_sds_destroy(json);

                    return FLB_RETRY;
                }
            }

            if (flb_sds_len(json) > 65535) {
                flb_plg_debug(ctx->ins, "record size exceeds maximum datagram size : %zu", flb_sds_len(json));
            }

            send_result = send(ctx->endpoint_descriptor,
                               json,
                               flb_sds_len(json),
                               0);

            if (send_result == -1) {
                flb_log_event_decoder_destroy(&log_decoder);
                flb_sds_destroy(json);

                return FLB_RETRY;
            }
        }

        flb_sds_destroy(json);
    }

    flb_log_event_decoder_destroy(&log_decoder);

    return FLB_OK;
}

static int deliver_chunks_msgpack(struct flb_out_udp *ctx,
                                  const char *tag, int tag_len,
                                  const void *in_data, size_t in_size)
{
    size_t off = 0;
    ssize_t send_result;
    size_t previous_offset;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) in_data, in_size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_RETRY;
    }

    previous_offset = 0;

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        off = log_decoder.offset;

        if ((off - previous_offset) > 65535) {
            flb_plg_debug(ctx->ins, "record size exceeds maximum datagram size : %zu", (off - previous_offset));
        }

        send_result = send(ctx->endpoint_descriptor,
                           &((char *) in_data)[previous_offset],
                           off - previous_offset,
                           0);

        if (send_result == -1) {
            flb_log_event_decoder_destroy(&log_decoder);

            return FLB_RETRY;
        }

        previous_offset = off;
    }

    flb_log_event_decoder_destroy(&log_decoder);

    return FLB_OK;
}

static void cb_udp_flush(struct flb_event_chunk *event_chunk,
                         struct flb_output_flush *out_flush,
                         struct flb_input_instance *i_ins,
                         void *out_context,
                         struct flb_config *config)
{
    int ret = FLB_ERROR;
    struct flb_out_udp *ctx = out_context;

    (void) i_ins;

    if (ctx->ra_raw_message_key != NULL) {
        ret = deliver_chunks_raw(ctx,
                                 event_chunk->tag,
                                 flb_sds_len(event_chunk->tag),
                                 event_chunk->data,
                                 event_chunk->size);
    }
    else if (ctx->out_format == FLB_PACK_JSON_FORMAT_NONE) {
        ret = deliver_chunks_msgpack(ctx,
                                     event_chunk->tag,
                                     flb_sds_len(event_chunk->tag),
                                     event_chunk->data,
                                     event_chunk->size);
    }
    else {
        ret = deliver_chunks_json(ctx,
                                  event_chunk->tag,
                                  flb_sds_len(event_chunk->tag),
                                  event_chunk->data,
                                  event_chunk->size,
                                  config);
    }

    return FLB_OUTPUT_RETURN(ret);
}

static int cb_udp_exit(void *data, struct flb_config *config)
{
    struct flb_out_udp *ctx = data;

    flb_udp_conf_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", "json_lines",
     0, FLB_FALSE, 0,
     "Specify the payload format, supported formats: msgpack, json, "
     "json_lines or json_stream."
    },

    {
     FLB_CONFIG_MAP_STR, "json_date_format", "double",
     0, FLB_FALSE, 0,
     FBL_PACK_JSON_DATE_FORMAT_DESCRIPTION
    },

    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_out_udp, json_date_key),
     "Specify the name of the date field in output."
    },

    {
     FLB_CONFIG_MAP_STR, "raw_message_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_udp, raw_message_key),
     "use a raw message key for the message."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_udp_plugin = {
    .name           = "udp",
    .description    = "UDP Output",
    .cb_init        = cb_udp_init,
    .cb_flush       = cb_udp_flush,
    .cb_exit        = cb_udp_exit,
    .config_map     = config_map,

    .workers        = 2,
    .flags          = FLB_OUTPUT_NET,
};
