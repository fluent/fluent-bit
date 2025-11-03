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
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <string.h>

#include "vivo.h"
#include "vivo_http.h"
#include "vivo_stream.h"

static msgpack_object *find_map_value(msgpack_object *map,
                                      const char *key, size_t key_len)
{
    size_t i;

    if (!map || map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    for (i = 0; i < map->via.map.size; i++) {
        if (map->via.map.ptr[i].key.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (map->via.map.ptr[i].key.via.str.size == key_len &&
            strncmp(map->via.map.ptr[i].key.via.str.ptr, key, key_len) == 0) {
            return &map->via.map.ptr[i].val;
        }
    }

    return NULL;
}

static flb_sds_t format_logs(struct flb_input_instance *src_ins,
                             struct flb_event_chunk *event_chunk, struct flb_config *config)
{
    int len;
    int result;
    char *name;
    flb_sds_t out_js;
    flb_sds_t out_buf = NULL;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    int group_mismatch = FLB_FALSE;
    int is_otlp = FLB_FALSE;
    struct flb_log_event log_event;
    struct flb_log_event_decoder log_decoder;
    struct flb_mp_map_header mh;
    struct flb_mp_map_header root_map;
    struct flb_mp_map_header otlp_map;
    struct flb_mp_map_header group_map;
    msgpack_object *group_metadata = NULL;
    msgpack_object *group_attributes = NULL;
    msgpack_object *schema_value = NULL;
    msgpack_object *resource_value = NULL;
    msgpack_object *scope_value = NULL;

    result = flb_log_event_decoder_init(&log_decoder,
                                        (char *) event_chunk->data,
                                        event_chunk->size);

    if (result != FLB_EVENT_DECODER_SUCCESS) {
        return NULL;
    }

    out_buf = flb_sds_create_size((event_chunk->size * 2) / 4);
    if (!out_buf) {
        flb_errno();
        return NULL;
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /*
     * Here is an example of the packaging done for Logs
     *
     * {
     *    "source_type": "forward",
     *    "source_name": "forward.0",
     *    "tag": "dummy.0",
     *    "records": [
     *     {
     *        "timestamp": 1759591426808913765,
     *        "metadata": {
     *          "level": "info"
     *        },
     *        "message": "dummy"
     *      },
     *     {
     *        "timestamp": 1759591426908563348,
     *        "metadata": {
     *          "level": "debug",
     *          "service": "auth"
     *        },
     *        "message": "dummy"
     *      }
     *    ]
     * }
     */

    flb_mp_map_header_init(&root_map, &tmp_pck);

    /* source_type: internal type of the plugin */
    flb_mp_map_header_append(&root_map);
    name = src_ins->p->name;
    len = strlen(name);

    msgpack_pack_str(&tmp_pck, 11);
    msgpack_pack_str_body(&tmp_pck, "source_type", 11);
    msgpack_pack_str(&tmp_pck, len);
    msgpack_pack_str_body(&tmp_pck, name, len);

    /* source_name: internal name or alias set by the user */
    flb_mp_map_header_append(&root_map);
    name = (char *) flb_input_name(src_ins);
    len = strlen(name);
    msgpack_pack_str(&tmp_pck, 11);
    msgpack_pack_str_body(&tmp_pck, "source_name", 11);
    msgpack_pack_str(&tmp_pck, len);
    msgpack_pack_str_body(&tmp_pck, name, len);

    /* tag */
    flb_mp_map_header_append(&root_map);
    msgpack_pack_str(&tmp_pck, 3);
    msgpack_pack_str_body(&tmp_pck, "tag", 3);
    msgpack_pack_str(&tmp_pck, flb_sds_len(event_chunk->tag));
    msgpack_pack_str_body(&tmp_pck, event_chunk->tag, flb_sds_len(event_chunk->tag));

    /* records */
    flb_mp_map_header_append(&root_map);
    msgpack_pack_str(&tmp_pck, 7);
    msgpack_pack_str_body(&tmp_pck, "records", 7);

    flb_mp_array_header_init(&mh, &tmp_pck);

    while ((result = flb_log_event_decoder_next(
                        &log_decoder,
                        &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        if (log_event.group_metadata != NULL) {
            if (group_metadata == NULL) {
                group_metadata = log_event.group_metadata;
            }
            else if (group_metadata != log_event.group_metadata) {
                group_mismatch = FLB_TRUE;
            }
        }

        if (log_event.group_attributes != NULL) {
            if (group_attributes == NULL) {
                group_attributes = log_event.group_attributes;
            }
            else if (group_attributes != log_event.group_attributes) {
                group_mismatch = FLB_TRUE;
            }
        }

        flb_mp_array_header_append(&mh);

        /*
         * [[TIMESTAMP, {"....": "...", ...MORE_METADATA}], {RECORD CONTENT}]
         */
        msgpack_pack_array(&tmp_pck, 2);
        msgpack_pack_array(&tmp_pck, 2);
        msgpack_pack_uint64(&tmp_pck, flb_time_to_nanosec(&log_event.timestamp));

        /* pack metadata */
        msgpack_pack_object(&tmp_pck, *log_event.metadata);

        /* pack the remaining content */
        msgpack_pack_object(&tmp_pck, *log_event.body);
    }

    flb_mp_array_header_end(&mh);

    if (group_mismatch == FLB_FALSE &&
        (group_metadata != NULL || group_attributes != NULL)) {
        if (group_metadata != NULL) {
            schema_value = find_map_value(group_metadata, "schema", 6);
        }

        if (schema_value &&
            schema_value->type == MSGPACK_OBJECT_STR &&
            schema_value->via.str.size == 4 &&
            strncmp(schema_value->via.str.ptr, "otlp", 4) == 0) {
            is_otlp = FLB_TRUE;
        }

        if (is_otlp == FLB_TRUE) {
            resource_value = NULL;
            scope_value = NULL;

            if (group_attributes != NULL &&
                group_attributes->type == MSGPACK_OBJECT_MAP) {
                resource_value = find_map_value(group_attributes, "resource", 8);
                scope_value = find_map_value(group_attributes, "scope", 5);
            }

            flb_mp_map_header_append(&root_map);
            msgpack_pack_str(&tmp_pck, 4);
            msgpack_pack_str_body(&tmp_pck, "otlp", 4);

            flb_mp_map_header_init(&otlp_map, &tmp_pck);

            if (resource_value != NULL) {
                flb_mp_map_header_append(&otlp_map);
                msgpack_pack_str(&tmp_pck, 8);
                msgpack_pack_str_body(&tmp_pck, "resource", 8);
                msgpack_pack_object(&tmp_pck, *resource_value);
            }

            if (scope_value != NULL) {
                flb_mp_map_header_append(&otlp_map);
                msgpack_pack_str(&tmp_pck, 5);
                msgpack_pack_str_body(&tmp_pck, "scope", 5);
                msgpack_pack_object(&tmp_pck, *scope_value);
            }

            flb_mp_map_header_end(&otlp_map);
        }
        else {
            flb_mp_map_header_append(&root_map);
            msgpack_pack_str(&tmp_pck, 9);
            msgpack_pack_str_body(&tmp_pck, "flb_group", 9);

            flb_mp_map_header_init(&group_map, &tmp_pck);

            if (group_metadata != NULL) {
                flb_mp_map_header_append(&group_map);
                msgpack_pack_str(&tmp_pck, 8);
                msgpack_pack_str_body(&tmp_pck, "metadata", 8);
                msgpack_pack_object(&tmp_pck, *group_metadata);
            }

            if (group_attributes != NULL) {
                flb_mp_map_header_append(&group_map);
                msgpack_pack_str(&tmp_pck, 4);
                msgpack_pack_str_body(&tmp_pck, "body", 4);
                msgpack_pack_object(&tmp_pck, *group_attributes);
            }

            flb_mp_map_header_end(&group_map);
        }
    }

    flb_mp_map_header_end(&root_map);

    /* Release the unpacker */
    flb_log_event_decoder_destroy(&log_decoder);

    /* Convert the complete msgpack structure to JSON */
    out_js = flb_msgpack_raw_to_json_sds(tmp_sbuf.data, tmp_sbuf.size,
                                         config->json_escape_unicode);

    msgpack_sbuffer_destroy(&tmp_sbuf);

    if (!out_js) {
        flb_sds_destroy(out_buf);
        return NULL;
    }

    /* append a newline */
    if (flb_sds_cat_safe(&out_js, "\n", 1) < 0) {
        flb_sds_destroy(out_js);
        flb_sds_destroy(out_buf);
        return NULL;
    }

    /* Replace out_buf with the complete JSON */
    flb_sds_destroy(out_buf);
    return out_js;
}

static int logs_event_chunk_append(struct vivo_exporter *ctx,
                                   struct flb_input_instance *src_ins,
                                   struct flb_event_chunk *event_chunk,
                                   struct flb_config *config)
{
    size_t len;
    flb_sds_t json;
    struct vivo_stream_entry *entry;

    json = format_logs(src_ins, event_chunk, config);
    if (!json) {
        flb_plg_error(ctx->ins, "cannot convert logs chunk to JSON");
        return -1;
    }

    /* append content to the stream */
    len = flb_sds_len(json);
    entry = vivo_stream_append(ctx->stream_logs, json, len);

    flb_sds_destroy(json);

    if (!entry) {
        flb_plg_error(ctx->ins, "cannot append JSON log to stream");
        return -1;
    }

    return 0;
}

static int metrics_traces_event_chunk_append(struct vivo_exporter *ctx,
                                             struct vivo_stream *vs,
                                             struct flb_event_chunk *event_chunk,
                                             struct flb_config *config)
{
    size_t len;
    flb_sds_t json;
    struct vivo_stream_entry *entry;

    /* Convert msgpack to readable JSON format */
    json = flb_msgpack_raw_to_json_sds(event_chunk->data, event_chunk->size,
                                       config->json_escape_unicode);
    if (!json) {
        flb_plg_error(ctx->ins, "cannot convert metrics chunk to JSON");
        return -1;
    }

    flb_sds_cat_safe(&json, "\n", 1);

    /* append content to the stream */
    len = flb_sds_len(json);
    entry = vivo_stream_append(vs, json, len);

    flb_sds_destroy(json);

    if (!entry) {
        flb_plg_error(ctx->ins, "cannot append JSON log to stream");
        return -1;
    }

    return 0;
}

static int cb_vivo_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    struct vivo_exporter *ctx;

    flb_output_net_default("0.0.0.0", 2025 , ins);

    ctx = flb_calloc(1, sizeof(struct vivo_exporter));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->config = config;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    flb_output_set_context(ins, ctx);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* Create Streams */
    ctx->stream_logs = vivo_stream_create(ctx);
    if (!ctx->stream_logs) {
        return -1;
    }

    ctx->stream_metrics = vivo_stream_create(ctx);
    if (!ctx->stream_metrics) {
        return -1;
    }

    ctx->stream_traces = vivo_stream_create(ctx);
    if (!ctx->stream_traces) {
        return -1;
    }

    /* HTTP Server context */
    ctx->http = vivo_http_server_create(ctx,
                                        ins->host.name, ins->host.port, config);
    if (!ctx->http) {
        flb_plg_error(ctx->ins, "could not initialize HTTP server, aborting");
        return -1;
    }

    /* Start HTTP Server */
    ret = vivo_http_server_start(ctx->http);
    if (ret == -1) {
        return -1;
    }

    flb_plg_info(ctx->ins, "listening iface=%s tcp_port=%d",
                 ins->host.name, ins->host.port);

    return 0;
}

static void cb_vivo_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *ins, void *out_context,
                          struct flb_config *config)
{
    int ret = -1;
    struct vivo_exporter *ctx = out_context;

#ifdef FLB_HAVE_METRICS
    if (event_chunk->type == FLB_EVENT_TYPE_METRICS) {
        ret = metrics_traces_event_chunk_append(ctx, ctx->stream_metrics, event_chunk, config);
    }
#endif
    if (event_chunk->type == FLB_EVENT_TYPE_LOGS) {
        ret = logs_event_chunk_append(ctx, ins, event_chunk, config);
    }
    else if (event_chunk->type == FLB_EVENT_TYPE_TRACES) {
        ret = metrics_traces_event_chunk_append(ctx, ctx->stream_traces, event_chunk, config);
    }

    if (ret == 0) {
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    FLB_OUTPUT_RETURN(FLB_ERROR);
}

static int cb_vivo_exit(void *data, struct flb_config *config)
{
    struct vivo_exporter *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->http) {
        vivo_http_server_stop(ctx->http);
        vivo_http_server_destroy(ctx->http);
    }

    vivo_stream_destroy(ctx->stream_logs);
    vivo_stream_destroy(ctx->stream_metrics);
    vivo_stream_destroy(ctx->stream_traces);

    flb_free(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "empty_stream_on_read", "off",
     0, FLB_TRUE, offsetof(struct vivo_exporter, empty_stream_on_read),
     "If enabled, when an HTTP client consumes the data from a stream, the queue "
     "content will be removed"
    },

    {
     FLB_CONFIG_MAP_SIZE, "stream_queue_size", "20M",
     0, FLB_TRUE, offsetof(struct vivo_exporter, stream_queue_size),
     "Specify the maximum queue size per stream. Each specific stream for logs, metrics "
     "and traces can hold up to 'stream_queue_size' bytes."
    },

    {
     FLB_CONFIG_MAP_STR, "http_cors_allow_origin", NULL,
     0, FLB_TRUE, offsetof(struct vivo_exporter, http_cors_allow_origin),
     "Specify the value for the HTTP Access-Control-Allow-Origin header (CORS)"
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_vivo_exporter_plugin = {
    .name        = "vivo_exporter",
    .description = "Vivo Exporter",
    .cb_init     = cb_vivo_init,
    .cb_flush    = cb_vivo_flush,
    .cb_exit     = cb_vivo_exit,
    .flags       = FLB_OUTPUT_NET,
    .event_type  = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS | FLB_OUTPUT_TRACES,
    .config_map  = config_map,
    .workers     = 1,
};
