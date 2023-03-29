/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#include "vivo.h"
#include "vivo_http.h"
#include "vivo_stream.h"

static flb_sds_t format_logs(struct flb_event_chunk *event_chunk)
{
    int i;
    int ok = MSGPACK_UNPACK_SUCCESS;
    int map_size;
    size_t off = 0;
    flb_sds_t out_js;
    flb_sds_t out_buf = NULL;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_object *obj;
    msgpack_object *k;
    msgpack_object *v;
    struct flb_time tms;
    const char *data;
    size_t bytes;

    data = event_chunk->data;
    bytes = event_chunk->size;

    out_buf = flb_sds_create_size((bytes * 2) / 4);
    if (!out_buf) {
        flb_errno();
        return NULL;
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);


    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == ok) {
        /* Each array must have two entries: time and record */
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }
        if (root.via.array.size != 2) {
            continue;
        }

        /* Unpack time */
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        /* Get the record/map */
        map = root.via.array.ptr[1];
        if (map.type != MSGPACK_OBJECT_MAP) {
            continue;
        }
        map_size = map.via.map.size;


        /*
         * If the caller specified FLB_PACK_JSON_DATE_FLUENT, we format the data
         * by using the following structure:
         *
         * [[TIMESTAMP, {"_tag": "...", ...MORE_METADATA}], {RECORD CONTENT}]
         */
        msgpack_pack_array(&tmp_pck, 2);
        msgpack_pack_array(&tmp_pck, 2);
        msgpack_pack_uint64(&tmp_pck, flb_time_to_nanosec(&tms));

        /* add tag only */
        msgpack_pack_map(&tmp_pck, 1);

        msgpack_pack_str(&tmp_pck, 4);
        msgpack_pack_str_body(&tmp_pck, "_tag", 4);
        msgpack_pack_str(&tmp_pck, flb_sds_len(event_chunk->tag));
        msgpack_pack_str_body(&tmp_pck, event_chunk->tag, flb_sds_len(event_chunk->tag));

        /* pack the remaining content */
        msgpack_pack_map(&tmp_pck, map_size);

        /* Append remaining keys/values */
        for (i = 0; i < map_size; i++) {
            k = &map.via.map.ptr[i].key;
            v = &map.via.map.ptr[i].val;
            msgpack_pack_object(&tmp_pck, *k);
            msgpack_pack_object(&tmp_pck, *v);
        }

        /* Concatenate by using break lines */
        out_js = flb_msgpack_raw_to_json_sds(tmp_sbuf.data, tmp_sbuf.size);
        if (!out_js) {
            flb_sds_destroy(out_buf);
            msgpack_sbuffer_destroy(&tmp_sbuf);
            msgpack_unpacked_destroy(&result);
            return NULL;
        }

        /*
         * One map record has been converted, now append it to the
         * outgoing out_buf sds variable.
         */
        flb_sds_cat_safe(&out_buf, out_js, flb_sds_len(out_js));
        flb_sds_cat_safe(&out_buf, "\n", 1);

        flb_sds_destroy(out_js);
        msgpack_sbuffer_clear(&tmp_sbuf);
    }

    /* Release the unpacker */
    msgpack_unpacked_destroy(&result);

    msgpack_sbuffer_destroy(&tmp_sbuf);

    return out_buf;
}

static int logs_event_chunk_append(struct vivo_exporter *ctx,
                                  struct flb_event_chunk *event_chunk)
{
    size_t len;
    flb_sds_t json;
    struct vivo_stream_entry *entry;


    json = format_logs(event_chunk);
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
                                             struct flb_event_chunk *event_chunk)
{
    size_t len;
    flb_sds_t json;
    struct vivo_stream_entry *entry;

    /* Convert msgpack to readable JSON format */
    json = flb_msgpack_raw_to_json_sds(event_chunk->data, event_chunk->size);
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
        ret = metrics_traces_event_chunk_append(ctx, ctx->stream_metrics, event_chunk);
    }
#endif
    if (event_chunk->type == FLB_EVENT_TYPE_LOGS) {
        ret = logs_event_chunk_append(ctx, event_chunk);
    }
    else if (event_chunk->type == FLB_EVENT_TYPE_TRACES) {
        ret = metrics_traces_event_chunk_append(ctx, ctx->stream_traces, event_chunk);
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
