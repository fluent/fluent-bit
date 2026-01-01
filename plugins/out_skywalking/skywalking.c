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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include "skywalking.h"

#define DEFAULT_SW_OAP_HOST "127.0.0.1"
#define DEFAULT_SW_OAP_PORT 12800
#define DEFAULT_SW_SVC_NAME "sw-service"
#define DEFAULT_SW_INS_NAME "fluent-bit"
#define DEFAULT_SW_LOG_PATH "/v3/logs"

static void sw_output_ctx_destroy(struct flb_output_sw* ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_sds_destroy(ctx->http_scheme);
    flb_sds_destroy(ctx->uri);
    flb_free(ctx);
}

static int cb_sw_init(struct flb_output_instance *ins,
                      struct flb_config *config, void *data)
{
    int ret;
    int io_flags;
    struct flb_output_sw *ctx;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_output_sw));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        sw_output_ctx_destroy(ctx);
        return -1;
    }

    flb_output_net_default(DEFAULT_SW_OAP_HOST, DEFAULT_SW_OAP_PORT, ctx->ins);

    ctx->uri = flb_sds_create(DEFAULT_SW_LOG_PATH);
    if (!ctx->uri) {
        flb_plg_error(ctx->ins, "failed to configure endpoint");
        sw_output_ctx_destroy(ctx);
        return -1;
    }

    if (!ctx->svc_name) {
        flb_plg_error(ctx->ins, "failed to configure service name");
        sw_output_ctx_destroy(ctx);
        return -1;
    }

    if (!ctx->svc_inst_name) {
        flb_plg_error(ctx->ins, "failed to configure instance name");
        sw_output_ctx_destroy(ctx);
        return -1;
    }

    flb_plg_debug(ctx->ins, "configured %s/%s", ctx->svc_name, ctx->svc_inst_name);
    flb_plg_debug(ctx->ins, "OAP address is %s:%d", ins->host.name, ins->host.port);

    /* scheme configuration */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        ctx->http_scheme = flb_sds_create("https://");
    }
    else {
        io_flags = FLB_IO_TCP;
        ctx->http_scheme = flb_sds_create("http://");
    }

    /* configure upstream instance */
    ctx->u = flb_upstream_create(config, ins->host.name, ins->host.port, io_flags, ins->tls);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "failed to create upstream context");
        sw_output_ctx_destroy(ctx);
        return -1;
    }

    flb_output_upstream_set(ctx->u, ins);

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);
    flb_output_set_http_debug_callbacks(ins);

    return 0;
}

static int64_t timestamp_format(const struct flb_time* tms)
{
    int64_t timestamp = 0;

    /* Format the time, use milliseconds precision not nanoseconds */
    timestamp = tms->tm.tv_sec * 1000;
    timestamp += tms->tm.tv_nsec / 1000000;

    /* round up if necessary */
    if (tms->tm.tv_nsec % 1000000 >= 500000) {
        ++timestamp;
    }
    return timestamp;
}

static void sw_msgpack_pack_kv_str(msgpack_packer* pk, const char* key,
                                   size_t key_len, const char *value,
                                   size_t value_len)
{
    msgpack_pack_str(pk, key_len);
    msgpack_pack_str_body(pk, key, key_len);
    msgpack_pack_str(pk, value_len);
    msgpack_pack_str_body(pk, value, value_len);
}

static void sw_msgpack_pack_kv_int64_t(msgpack_packer* pk, const char* key,
                                       size_t key_len, int64_t value)
{
    msgpack_pack_str(pk, key_len);
    msgpack_pack_str_body(pk, key, key_len);
    msgpack_pack_int64(pk, value);
}

static void sw_msgpack_pack_log_body(msgpack_packer* pk,
                                     msgpack_object* obj, size_t obj_size,
                                     struct flb_config *config)
{
    int i, j = 0;
    int log_entry_num = 0;
    msgpack_sbuffer sbuf;
    msgpack_packer body_pk;
    msgpack_object key;
    msgpack_object value;
    flb_sds_t out_body_str;
    size_t out_body_str_len;
    int* valid_log_entry = NULL;

    valid_log_entry = (int*)flb_malloc(obj_size * sizeof(int));
    if (!valid_log_entry) {
        flb_errno();
        return;
    }

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&body_pk, &sbuf, msgpack_sbuffer_write);

    for (i = 0; i < obj_size; ++i) {
        key = obj->via.map.ptr[i].key;
        value = obj->via.map.ptr[i].val;

        if (key.type != MSGPACK_OBJECT_STR ||
            value.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        valid_log_entry[j] = i;
        ++j;
        ++log_entry_num;
    }

    msgpack_pack_map(&body_pk, log_entry_num);

    for (i = 0; i < log_entry_num; ++i) {
        key = obj->via.map.ptr[valid_log_entry[i]].key;
        value = obj->via.map.ptr[valid_log_entry[i]].val;
        sw_msgpack_pack_kv_str(&body_pk, key.via.str.ptr, key.via.str.size,
                               value.via.str.ptr, value.via.str.size);
    }

    out_body_str = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size,
                                               config->json_escape_unicode);
    if (!out_body_str) {
        msgpack_sbuffer_destroy(&sbuf);
        flb_free(valid_log_entry);
        return;
    }
    out_body_str_len = flb_sds_len(out_body_str);

    msgpack_pack_str(pk, 4);
    msgpack_pack_str_body(pk, "body", 4);
    msgpack_pack_map(pk, 1);

    /* body['json'] */
    msgpack_pack_str(pk, 4);
    msgpack_pack_str_body(pk, "json", 4);
    msgpack_pack_map(pk, 1);

    /* body['json']['json'] */
    msgpack_pack_str(pk, 4);
    msgpack_pack_str_body(pk, "json", 4);
    msgpack_pack_str(pk, out_body_str_len);
    msgpack_pack_str_body(pk, out_body_str, out_body_str_len);

    flb_sds_destroy(out_body_str);
    msgpack_sbuffer_destroy(&sbuf);
    flb_free(valid_log_entry);
}

static int sw_format(struct flb_output_sw* ctx, const void *data, size_t bytes,
                     void** buf, size_t* buf_len, struct flb_config *config)
{
    int ret = 0;
    int chunk_size = 0;
    uint32_t map_size;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    msgpack_object map;
    int64_t timestamp;
    flb_sds_t out_str;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    chunk_size = flb_mp_count(data, bytes);
    flb_plg_debug(ctx->ins, "%i messages flushed", chunk_size);

    msgpack_pack_array(&pk, chunk_size);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        timestamp = timestamp_format(&log_event.timestamp);

        map = *log_event.body;
        map_size = map.via.map.size;

        msgpack_pack_map(&pk, 4);

        sw_msgpack_pack_kv_int64_t(&pk, "timestamp", 9, timestamp);
        sw_msgpack_pack_kv_str(&pk, "service", 7, ctx->svc_name,
                               flb_sds_len(ctx->svc_name));
        sw_msgpack_pack_kv_str(&pk, "serviceInstance", 15,
                               ctx->svc_inst_name, flb_sds_len(ctx->svc_inst_name));
        sw_msgpack_pack_log_body(&pk, &map, map_size, config);
    }

    out_str = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size, config->json_escape_unicode);
    if (!out_str) {
        ret = -1;
        goto done;
    }
    else {
        ret = 0;
    }

    *buf = out_str;
    *buf_len = flb_sds_len(out_str);

done:
    msgpack_sbuffer_destroy(&sbuf);
    flb_log_event_decoder_destroy(&log_decoder);

    return ret;
}

static int mock_oap_request(struct flb_http_client* client, int mock_status)
{
    client->resp.status = mock_status;
    return 0;
}

static bool check_sw_under_test()
{
    if (getenv("FLB_SW_PLUGIN_UNDER_TEST") != NULL) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

static void cb_sw_flush(struct flb_event_chunk *event_chunk,
                        struct flb_output_flush *out_flush,
                        struct flb_input_instance *i_ins,
                        void *out_context, struct flb_config *config)
{
    int flush_ret = -1;
    int tmp_ret = -1;
    struct flb_output_sw *ctx = out_context;
    struct flb_connection *conn = NULL;
    struct flb_http_client *client = NULL;
    void* buf = NULL;
    size_t buf_len;
    size_t sent_size;

    tmp_ret = sw_format(ctx,
                        event_chunk->data,
                        event_chunk->size,
                        &buf, &buf_len, config);
    if (tmp_ret != 0) {
        flb_plg_error(ctx->ins, "failed to create buffer");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    conn = flb_upstream_conn_get(ctx->u);
    if (!conn) {
        flb_plg_error(ctx->ins, "failed to establish connection to %s:%i",
                ctx->ins->host.name, ctx->ins->host.port);
        flb_sds_destroy(buf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    client = flb_http_client(conn, FLB_HTTP_POST, ctx->uri,
            (const char*)buf, buf_len, ctx->ins->host.name, ctx->ins->host.port,
            NULL, 0);
    if (!client) {
        flb_plg_error(ctx->ins, "failed to create HTTP client");
        flb_sds_destroy(buf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    if (ctx->auth_token && flb_sds_len(ctx->auth_token) != 0) {
        flb_http_add_header(client, "Authentication", 14,
                            ctx->auth_token, strlen(ctx->auth_token));
    }

    flb_http_add_header(client, "Content-Type", 12,
                    "application/json", 16);
    flb_http_add_header(client, "User-Agent", 10,
                        "Fluent-Bit", 10);

    if (check_sw_under_test() == FLB_TRUE) {
        tmp_ret = mock_oap_request(client, 200);
    }
    else {
        tmp_ret = flb_http_do(client, &sent_size);
    }

    if (tmp_ret == 0) {
        flb_plg_debug(ctx->ins, "%s:%i, HTTP status=%i", ctx->ins->host.name,
                ctx->ins->host.port, client->resp.status);

        if (client->resp.status < 200 || client->resp.status > 205) {
            flush_ret = FLB_RETRY;
        }
        else {
            flush_ret = FLB_OK;
        }
    }
    else {
        flb_plg_error(ctx->ins, "failed to flush buffer to %s:%i",
                ctx->ins->host.name, ctx->ins->host.port);
        flush_ret = FLB_RETRY;
    }

    flb_sds_destroy(buf);
    flb_http_client_destroy(client);
    flb_upstream_conn_release(conn);

    FLB_OUTPUT_RETURN(flush_ret);
}

static int cb_sw_exit(void *data, struct flb_config *config)
{
    struct flb_output_sw *ctx;

    ctx = (struct flb_output_sw*)data;
    sw_output_ctx_destroy(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "auth_token", NULL,
        0, FLB_TRUE, offsetof(struct flb_output_sw, auth_token),
        "Auth token for SkyWalking OAP"
    },
    {
        FLB_CONFIG_MAP_STR, "svc_name", DEFAULT_SW_SVC_NAME,
        0, FLB_TRUE, offsetof(struct flb_output_sw, svc_name),
        "Service name"
    },
    {
        FLB_CONFIG_MAP_STR, "svc_inst_name", DEFAULT_SW_INS_NAME,
        0, FLB_TRUE, offsetof(struct flb_output_sw, svc_inst_name),
        "Instance name"
    },
    {0}
};

struct flb_output_plugin out_skywalking_plugin = {
    .name = "skywalking",
    .description = "Send logs into log collector on SkyWalking OAP",
    .cb_init = cb_sw_init,
    .cb_flush = cb_sw_flush,
    .cb_exit = cb_sw_exit,
    .flags = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .config_map = config_map
};
