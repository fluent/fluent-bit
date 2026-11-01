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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_uri.h>

#include <cfl/cfl_atomic.h>

#include <msgpack.h>

#include <string.h>

#include "manticore.h"

static flb_sds_t build_bulk_uri(const char *table)
{
    flb_sds_t uri;
    flb_sds_t encoded;

    encoded = flb_uri_encode(table, strlen(table));
    if (encoded == NULL) {
        return NULL;
    }

    uri = flb_sds_create(FLB_MANTICORE_BULK_IMPORT_URI);
    if (uri != NULL &&
        flb_sds_cat_safe(&uri, encoded, flb_sds_len(encoded)) != 0) {
        flb_sds_destroy(uri);
        uri = NULL;
    }
    flb_sds_destroy(encoded);
    return uri;
}

static int key_equals(const msgpack_object *key, const char *name)
{
    size_t len;

    if (key->type != MSGPACK_OBJECT_STR || name == NULL) {
        return FLB_FALSE;
    }

    len = strlen(name);
    if (key->via.str.size != len) {
        return FLB_FALSE;
    }

    return memcmp(key->via.str.ptr, name, len) == 0;
}

static int validate_record(struct flb_out_manticore *ctx,
                           const msgpack_object *body)
{
    int i;
    const msgpack_object_kv *entry;

    if (body == NULL || body->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "log record body must be a map");
        return -1;
    }

    entry = body->via.map.ptr;
    for (i = 0; i < body->via.map.size; i++) {
        if (entry[i].key.type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "record keys must be strings");
            return -1;
        }
    }

    return 0;
}

static msgpack_object str_object(const char *str)
{
    msgpack_object obj;

    obj.type = MSGPACK_OBJECT_STR;
    obj.via.str.ptr = str;
    obj.via.str.size = strlen(str);
    return obj;
}

/*
 * Appends one record as one NDJSON line, converted to JSON in one call:
 * Regular sends {"<action>":{"table":<table>,"doc":<record>}}, Shared the bare
 * record, because its table is in the URI. The daemon takes the record's own
 * id, if any, as the document id, and gives an auto-id otherwise.
 */
static int format_record(struct flb_out_manticore *ctx,
                         const msgpack_object *body, flb_sds_t *payload)
{
    int ret;
    char *json;
    msgpack_object line;
    msgpack_object_kv action;
    msgpack_object_kv operation[2];

    line = *body;
    if (ctx->mode_type == MANTICORE_MODE_REGULAR) {
        operation[0].key = str_object("table");
        operation[0].val = str_object(ctx->table);
        operation[1].key = str_object("doc");
        operation[1].val = *body;
        action.key = str_object(ctx->bulk_action);
        action.val.type = MSGPACK_OBJECT_MAP;
        action.val.via.map.size = 2;
        action.val.via.map.ptr = operation;
        line.via.map.size = 1;
        line.via.map.ptr = &action;
    }

    json = flb_msgpack_to_json_str(1024, &line,
                                   ctx->config->json_escape_unicode);
    if (json == NULL) {
        return -1;
    }
    ret = flb_sds_cat_safe(payload, json, strlen(json));
    flb_free(json);
    if (ret == 0) {
        ret = flb_sds_cat_safe(payload, "\n", 1);
    }
    return ret;
}

static void inspect_item_status(const msgpack_object *item,
                                int *has_status, int *retryable)
{
    int i;
    msgpack_object action;
    msgpack_object key;
    msgpack_object value;

    if (item->type != MSGPACK_OBJECT_MAP || item->via.map.size != 1) {
        return;
    }

    action = item->via.map.ptr[0].val;
    if (action.type != MSGPACK_OBJECT_MAP) {
        return;
    }

    for (i = 0; i < action.via.map.size; i++) {
        key = action.via.map.ptr[i].key;
        value = action.via.map.ptr[i].val;
        if (!key_equals(&key, "status")) {
            continue;
        }

        if (value.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            *has_status = FLB_TRUE;
            if (value.via.u64 == 408 || value.via.u64 == 429 ||
                value.via.u64 >= 500) {
                *retryable = FLB_TRUE;
            }
            return;
        }
    }
}

static void inspect_response_items(const msgpack_object *items,
                                   int *has_status, int *retryable)
{
    int i;

    if (items->type != MSGPACK_OBJECT_ARRAY) {
        return;
    }

    for (i = 0; i < items->via.array.size; i++) {
        inspect_item_status(&items->via.array.ptr[i], has_status, retryable);
    }
}

static int response_ok(struct flb_out_manticore *ctx,
                       struct flb_http_client *client)
{
    int i;
    int ret;
    int root_type;
    int errors;
    int has_status;
    int retryable;
    char *packed;
    size_t packed_size;
    size_t offset;
    msgpack_object root;
    msgpack_object key;
    msgpack_object value;
    msgpack_unpacked result;

    packed = NULL;
    packed_size = 0;
    errors = -1;
    has_status = FLB_FALSE;
    retryable = FLB_FALSE;
    if (client->resp.payload_size > 0) {
        ret = flb_pack_json(client->resp.payload, client->resp.payload_size,
                            &packed, &packed_size, &root_type, NULL);
        if (ret == 0) {
            msgpack_unpacked_init(&result);
            offset = 0;
            ret = msgpack_unpack_next(&result, packed, packed_size, &offset);
            if (ret == MSGPACK_UNPACK_SUCCESS) {
                root = result.data;
                if (root.type == MSGPACK_OBJECT_MAP) {
                    for (i = 0; i < root.via.map.size; i++) {
                        key = root.via.map.ptr[i].key;
                        value = root.via.map.ptr[i].val;
                        if (key_equals(&key, "errors") &&
                            value.type == MSGPACK_OBJECT_BOOLEAN) {
                            errors = value.via.boolean;
                        }
                        else if (key_equals(&key, "items")) {
                            inspect_response_items(&value, &has_status, &retryable);
                        }
                    }
                }
            }
            msgpack_unpacked_destroy(&result);
        }
        flb_free(packed);
    }

    if (client->resp.status >= 200 && client->resp.status < 300) {
        if (errors == FLB_FALSE) {
            return FLB_OK;
        }

        if (errors == FLB_TRUE && retryable == FLB_TRUE) {
            flb_plg_warn(ctx->ins,
                         "Manticore /bulk returned a retryable item error");
            return FLB_RETRY;
        }

        flb_plg_error(ctx->ins, "invalid or failed Manticore /bulk response: %.*s",
                      (int) client->resp.payload_size,
                      client->resp.payload);
        return FLB_ERROR;
    }

    if (client->resp.payload_size > 0) {
        flb_plg_error(ctx->ins, "Manticore /bulk returned HTTP %d: %.*s",
                      client->resp.status,
                      (int) client->resp.payload_size,
                      client->resp.payload);
    }
    else {
        flb_plg_error(ctx->ins, "Manticore /bulk returned HTTP %d",
                      client->resp.status);
    }

    if (retryable == FLB_TRUE || client->resp.status == 408 ||
        client->resp.status == 429) {
        return FLB_RETRY;
    }

    if (client->resp.status >= 500 && has_status == FLB_FALSE) {
        return FLB_RETRY;
    }

    return FLB_ERROR;
}

static int shared_response(struct flb_out_manticore *ctx,
                           struct flb_http_client *client, const char *state)
{
    int i;
    int ret;
    int root_type;
    int records = 0;
    int errors = -1;
    int expected_state = FLB_FALSE;
    int empty_error = FLB_FALSE;
    int empty_code = FLB_FALSE;
    int machine_reply = FLB_FALSE;
    char *packed = NULL;
    size_t packed_size = 0;
    size_t offset = 0;
    size_t consumed = 0;
    msgpack_object root;
    msgpack_object key;
    msgpack_object value;
    msgpack_unpacked result;

    if (client->resp.payload_size > 0) {
        ret = flb_pack_json_recs(client->resp.payload, client->resp.payload_size,
                                &packed, &packed_size, &root_type, &records, &consumed);
        if (ret == 0 && records == 1) {
            /* The stream packer may accept a valid object before a malformed tail. */
            while (consumed < client->resp.payload_size &&
                   (client->resp.payload[consumed] == ' ' ||
                    client->resp.payload[consumed] == '\t' ||
                    client->resp.payload[consumed] == '\r' ||
                    client->resp.payload[consumed] == '\n')) {
                consumed++;
            }
            msgpack_unpacked_init(&result);
            ret = msgpack_unpack_next(&result, packed, packed_size, &offset);
            if (ret == MSGPACK_UNPACK_SUCCESS &&
                offset == packed_size && consumed == client->resp.payload_size &&
                result.data.type == MSGPACK_OBJECT_MAP) {
                root = result.data;
                for (i = 0; i < root.via.map.size; i++) {
                    key = root.via.map.ptr[i].key;
                    value = root.via.map.ptr[i].val;
                    if (key_equals(&key, "errors") &&
                        value.type == MSGPACK_OBJECT_BOOLEAN) {
                        errors = value.via.boolean;
                    }
                    else if (key_equals(&key, "shared_state")) {
                        expected_state = key_equals(&value, state);
                        machine_reply = FLB_TRUE;
                    }
                    else if (key_equals(&key, "error_code")) {
                        empty_code = key_equals(&value, "");
                        if (!empty_code) {
                            machine_reply = FLB_TRUE;
                        }
                    }
                    else if (key_equals(&key, "error")) {
                        empty_error = key_equals(&value, "");
                    }
                }
            }
            msgpack_unpacked_destroy(&result);
        }
        flb_free(packed);
    }

    if (client->resp.status == 200 && errors == FLB_FALSE &&
        expected_state && empty_code && empty_error) {
        return FLB_OK;
    }

    flb_plg_error(ctx->ins, "Shared %s returned HTTP %d: %.*s", state,
                  client->resp.status, (int) client->resp.payload_size,
                  client->resp.payload ? client->resp.payload : "");
    if (strcmp(state, "staged") != 0 && client->resp.status >= 200 &&
        client->resp.status < 300) {
        /* A malformed success reply cannot establish control completion. */
        return FLB_RETRY;
    }
    if (!machine_reply && (client->resp.status == 408 ||
                          client->resp.status == 429 ||
                          client->resp.status >= 500)) {
        return FLB_RETRY;
    }
    return FLB_ERROR;
}

/*
 * The whole chunk is converted before anything is sent: a record that cannot
 * be sent fails the chunk, and none of its records reaches the daemon.
 */
static int format_events(struct flb_out_manticore *ctx,
                         const void *data, size_t bytes, flb_sds_t *payload)
{
    int ret;
    int result;
    int records;
    flb_sds_t body;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;

    ret = flb_log_event_decoder_init(&decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "could not initialize log event decoder: %s",
                      flb_log_event_decoder_get_error_description(ret));
        return FLB_RETRY;
    }

    body = flb_sds_create_size(bytes);
    if (body == NULL) {
        flb_log_event_decoder_destroy(&decoder);
        return FLB_RETRY;
    }

    result = FLB_OK;
    records = 0;
    while (result == FLB_OK &&
           flb_log_event_decoder_next(&decoder, &event) ==
           FLB_EVENT_DECODER_SUCCESS) {
        if (validate_record(ctx, event.body) != 0) {
            result = FLB_ERROR;
            break;
        }

        if (format_record(ctx, event.body, &body) != 0) {
            result = FLB_RETRY;
        }
        records++;
    }

    if (result == FLB_OK) {
        ret = flb_log_event_decoder_get_last_result(&decoder);
        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            flb_plg_error(ctx->ins, "could not decode log event: %s",
                          flb_log_event_decoder_get_error_description(ret));
            result = FLB_ERROR;
        }
        else if (records == 0) {
            flb_plg_error(ctx->ins, "bulk request requires at least one record");
            result = FLB_ERROR;
        }
    }
    flb_log_event_decoder_destroy(&decoder);

    if (result != FLB_OK) {
        flb_sds_destroy(body);
        return result;
    }
    *payload = body;
    return FLB_OK;
}

static int send_events(struct flb_out_manticore *ctx,
                       const void *data, size_t bytes)
{
    int ret;
    int result;
    size_t sent;
    flb_sds_t uri;
    flb_sds_t payload;
    struct flb_connection *connection;
    struct flb_http_client *client;

    result = format_events(ctx, data, bytes, &payload);
    if (result != FLB_OK) {
        return result;
    }

    connection = flb_upstream_conn_get(ctx->u);
    if (connection == NULL) {
        flb_sds_destroy(payload);
        return FLB_RETRY;
    }

    /*
     * After the first staged reply a Shared data request only joins the open
     * pool: a pool lost to a daemon restart or a cancel then fails the load
     * instead of starting a new pool with only the later records. Chosen
     * right before the request, once the connection is there.
     */
    uri = ctx->bulk_uri;
    if (ctx->mode_type == MANTICORE_MODE_SHARED &&
        cfl_atomic_load(&ctx->session_started)) {
        uri = ctx->join_uri;
    }

    client = flb_http_client(connection, FLB_HTTP_POST, uri,
                             payload, flb_sds_len(payload), NULL, 0, NULL, 0);
    if (client == NULL) {
        flb_upstream_conn_release(connection);
        flb_sds_destroy(payload);
        return FLB_RETRY;
    }

    flb_http_add_header(client, "Content-Type", 12,
                        "application/x-ndjson", 20);
    flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_buffer_size(client, ctx->buffer_size);

    if (ctx->http_user != NULL) {
        flb_http_basic_auth(client, ctx->http_user, ctx->http_passwd);
    }

    ret = flb_http_do(client, &sent);
    if (ret != 0) {
        result = FLB_RETRY;
    }
    else if (ctx->mode_type == MANTICORE_MODE_SHARED) {
        result = shared_response(ctx, client, "staged");
    }
    else {
        result = response_ok(ctx, client);
    }

    /*
     * Keep the connection for the next request only after a success: after a
     * failure the daemon may not have read the whole body. flb_http_do()
     * already drops it on a "Connection: close" reply.
     */
    if (result != FLB_OK) {
        flb_upstream_conn_recycle(connection, FLB_FALSE);
    }
    flb_http_client_destroy(client);
    flb_upstream_conn_release(connection);
    flb_sds_destroy(payload);
    return result;
}

/*
 * Sent once from cb_exit after every worker has stopped. Returns FLB_OK when
 * the load is published, FLB_ERROR when it is not, and FLB_RETRY when the
 * Finish was sent but its outcome is unknown.
 */
static int shared_commit(struct flb_out_manticore *ctx)
{
    int ret;
    int result = FLB_ERROR;
    size_t sent = 0;
    struct flb_connection *connection;
    struct flb_http_client *client;

    /*
     * cb_exit runs outside any coroutine, but on an async stream the connect
     * would switch to the last coroutine of this thread (with workers 0, a
     * finished flush). Nothing else uses the upstream now: make it blocking,
     * and without keepalive, so that the Finish opens a new connection
     * instead of one that the async flushes left in the pool, and does not
     * ask to keep it.
     */
    flb_stream_disable_async_mode(&ctx->u->base);
    ctx->u->base.net.keepalive = FLB_FALSE;
    flb_stream_disable_keepalive(&ctx->u->base);
    connection = flb_upstream_conn_get(ctx->u);
    if (connection == NULL) {
        return FLB_ERROR;
    }
    /*
     * HTTP/1.0: a blocking read that meets a closed connection ends the reply
     * instead of waiting for more data, so a lost reply has no status and
     * leaves the completion unknown rather than hanging.
     */
    client = flb_http_client(connection, FLB_HTTP_POST, ctx->bulk_uri,
                             "\n", 1, NULL, 0, NULL, FLB_HTTP_10);
    if (client != NULL) {
        flb_http_add_header(client, "Content-Type", 12,
                            "application/x-ndjson", 20);
        flb_http_buffer_size(client, ctx->buffer_size);
        if (ctx->http_user != NULL) {
            flb_http_basic_auth(client, ctx->http_user, ctx->http_passwd);
        }
        result = FLB_RETRY;
        ret = flb_http_do(client, &sent);
        if (ret == 0 && client->resp.status > 0) {
            result = shared_response(ctx, client, "published");
        }
        flb_http_client_destroy(client);
    }
    flb_upstream_conn_recycle(connection, FLB_FALSE);
    flb_upstream_conn_release(connection);
    return result;
}

static void manticore_conf_destroy(struct flb_out_manticore *ctx)
{
    if (ctx->u != NULL) {
        flb_upstream_destroy(ctx->u);
    }
    flb_sds_destroy(ctx->bulk_uri);
    flb_sds_destroy(ctx->join_uri);
    flb_free(ctx);
}

static int cb_manticore_init(struct flb_output_instance *ins,
                             struct flb_config *config, void *data)
{
    int io_flags;
    int ret;
    struct flb_out_manticore *ctx;

    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_out_manticore));
    if (ctx == NULL) {
        return -1;
    }

    ctx->ins = ins;
    ctx->config = config;
    flb_output_net_default("127.0.0.1", FLB_MANTICORE_DEFAULT_PORT, ins);

    ret = flb_output_config_map_set(ins, ctx);
    if (ret == -1 || ctx->table == NULL || ctx->table[0] == '\0') {
        flb_plg_error(ins, "table is required");
        manticore_conf_destroy(ctx);
        return -1;
    }

    if (strcasecmp(ctx->mode, "regular") == 0) {
        ctx->mode_type = MANTICORE_MODE_REGULAR;
    }
    else if (strcasecmp(ctx->mode, "shared") == 0) {
        ctx->mode_type = MANTICORE_MODE_SHARED;
    }
    else {
        flb_plg_error(ins, "mode must be Regular or Shared");
        manticore_conf_destroy(ctx);
        return -1;
    }

    /* Shared sends bare documents, which carry no action. */
    if (ctx->mode_type == MANTICORE_MODE_REGULAR &&
        strcasecmp(ctx->action, "insert") != 0 &&
        strcasecmp(ctx->action, "create") != 0) {
        flb_plg_error(ins, "action must be 'insert' or 'create'");
        manticore_conf_destroy(ctx);
        return -1;
    }

    ctx->bulk_action = strcasecmp(ctx->action, "create") == 0 ?
                       "create" : "insert";

    if (ctx->mode_type == MANTICORE_MODE_SHARED && ctx->shared_indexers < 0) {
        flb_plg_error(ins, "shared_indexers must be 0 or more");
        manticore_conf_destroy(ctx);
        return -1;
    }

#ifndef FLB_HAVE_METRICS
    /* Finish needs the delivery metrics to see dropped records. */
    if (ctx->mode_type == MANTICORE_MODE_SHARED) {
        flb_plg_error(ins, "Shared requires output delivery metrics");
        manticore_conf_destroy(ctx);
        return -1;
    }
#endif

    if (ctx->mode_type == MANTICORE_MODE_SHARED) {
        ctx->bulk_uri = build_bulk_uri(ctx->table);
    }
    else {
        ctx->bulk_uri = flb_sds_create(FLB_MANTICORE_BULK_URI);
    }
    if (ctx->bulk_uri == NULL) {
        manticore_conf_destroy(ctx);
        return -1;
    }
    /* The daemon reads the indexer count only from the request that starts the load. */
    if (ctx->mode_type == MANTICORE_MODE_SHARED &&
        (ctx->shared_indexers > 0 ?
         flb_sds_printf(&ctx->bulk_uri, "&shared=%d", ctx->shared_indexers) == NULL :
         flb_sds_cat_safe(&ctx->bulk_uri, "&shared", 7) < 0)) {
        manticore_conf_destroy(ctx);
        return -1;
    }
    if (ctx->mode_type == MANTICORE_MODE_SHARED) {
        ctx->join_uri = flb_sds_create(ctx->bulk_uri);
        if (ctx->join_uri == NULL ||
            flb_sds_cat_safe(&ctx->join_uri, "&shared_join", 12) < 0) {
            manticore_conf_destroy(ctx);
            return -1;
        }
    }

    io_flags = ins->use_tls == FLB_TRUE ? FLB_IO_TLS : FLB_IO_TCP;
    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    ctx->u = flb_upstream_create(config, ins->host.name, ins->host.port,
                                 io_flags, ins->tls);
    if (ctx->u == NULL) {
        manticore_conf_destroy(ctx);
        return -1;
    }
    flb_output_upstream_set(ctx->u, ins);

    flb_output_set_context(ins, ctx);
    flb_output_set_http_debug_callbacks(ins);
    return 0;
}

static void cb_manticore_flush(struct flb_event_chunk *event_chunk,
                               struct flb_output_flush *out_flush,
                               struct flb_input_instance *ins,
                               void *out_context,
                               struct flb_config *config)
{
    int ret;
    struct flb_out_manticore *ctx;

    (void) ins;
    (void) config;

    ctx = out_context;
    if (ctx->mode_type == MANTICORE_MODE_SHARED &&
        cfl_atomic_load(&ctx->session_failed)) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    ret = send_events(ctx, event_chunk->data, event_chunk->size);
    if (ctx->mode_type == MANTICORE_MODE_SHARED) {
        if (ret == FLB_OK) {
            cfl_atomic_store(&ctx->session_started, FLB_TRUE);
        }
        else if (ret == FLB_ERROR) {
            cfl_atomic_store(&ctx->session_failed, FLB_TRUE);
        }
    }
    FLB_OUTPUT_RETURN(ret);
}

/*
 * Runs once from cb_exit, after every worker has stopped. The load is complete
 * when no flush failed and Fluent Bit kept no task or chunk and dropped no
 * record; then the single Finish publishes it. The process exit code can no
 * longer report the outcome here, so it is logged.
 */
static void shared_exit(struct flb_out_manticore *ctx, struct flb_config *config)
{
    int mem_chunks = 0;
    int fs_chunks = 0;
    int tasks;
    int ret = FLB_OK;
    double dropped = -1;
    double exhausted = -1;
    char *name;

    tasks = flb_task_running_count(config);
    if (config->cio != NULL) {
        flb_storage_chunk_count(config, &mem_chunks, &fs_chunks);
    }
#ifdef FLB_HAVE_METRICS
    name = (char *) flb_output_name(ctx->ins);
    if (ctx->ins->cmt_dropped_records != NULL &&
        ctx->ins->cmt_retries_failed != NULL) {
        cmt_counter_get_val(ctx->ins->cmt_dropped_records, 1, &name, &dropped);
        cmt_counter_get_val(ctx->ins->cmt_retries_failed, 1, &name, &exhausted);
    }
#else
    (void) name;
#endif
    if (config->cio == NULL || tasks > 0 || mem_chunks > 0 || fs_chunks > 0 ||
        dropped != 0 || exhausted != 0) {
        ctx->session_failed = FLB_TRUE;
        flb_plg_error(ctx->ins,
                      "Shared incomplete: tasks=%d chunks=%d/%d dropped=%.0f exhausted=%.0f",
                      tasks, mem_chunks, fs_chunks, dropped, exhausted);
    }
    if (!ctx->session_failed && ctx->session_started) {
        ret = shared_commit(ctx);
        if (ret != FLB_OK) {
            ctx->session_failed = FLB_TRUE;
        }
    }
    if (ret == FLB_RETRY) {
        flb_plg_error(ctx->ins,
                      "Shared Finish completion unknown; coordinate recovery before replay");
    }
    else if (ctx->session_failed) {
        flb_plg_error(ctx->ins,
                      "Shared import not published; use PURGE BULK_IMPORT FROM TABLE %s "
                      "OPTION clear_sessions=1 to cancel staged data", ctx->table);
    }

    if (ctx->session_failed) {
        flb_plg_error(ctx->ins, "shared bulk_import failed: table=%s",
                      ctx->table);
    }
    else {
        flb_plg_info(ctx->ins, "shared bulk_import complete: table=%s",
                     ctx->table);
    }
}

static int cb_manticore_exit(void *data, struct flb_config *config)
{
    struct flb_out_manticore *ctx;

    ctx = data;
    if (ctx == NULL) {
        return 0;
    }

    if (ctx->mode_type == MANTICORE_MODE_SHARED) {
        shared_exit(ctx, config);
    }

    manticore_conf_destroy(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "table", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_manticore, table),
     "Target Manticore table (must already exist)"
    },
    {
     FLB_CONFIG_MAP_STR, "action", "insert",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, action),
     "Manticore bulk action: insert or create"
    },
    {
     FLB_CONFIG_MAP_STR, "mode", "Regular",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, mode),
     "Regular: normal bulk; Shared: coordinated finite bulk import"
    },
    {
     FLB_CONFIG_MAP_INT, "shared_indexers", "0",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, shared_indexers),
     "Shared: indexers the daemon starts, one disk chunk each; 0 lets the daemon choose"
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_size", "64K",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, buffer_size),
     "Maximum response buffer size"
    },
    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_manticore, http_user),
     "HTTP Basic authentication user"
    },
    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, http_passwd),
     "HTTP Basic authentication password"
    },
    {0}
};

static int cb_manticore_format_test(struct flb_config *config,
                                    struct flb_input_instance *ins,
                                    void *plugin_context,
                                    void *flush_ctx,
                                    int event_type,
                                    const char *tag, int tag_len,
                                    const void *data, size_t bytes,
                                    void **out_data, size_t *out_size)
{
    flb_sds_t payload;

    if (format_events(plugin_context, data, bytes, &payload) != FLB_OK) {
        return -1;
    }
    *out_data = payload;
    *out_size = flb_sds_len(payload);
    return 0;
}

struct flb_output_plugin out_manticore_plugin = {
    .name        = "manticore",
    .description = "Manticore Search output",
    .cb_init     = cb_manticore_init,
    .cb_pre_run  = NULL,
    .cb_flush    = cb_manticore_flush,
    .cb_exit     = cb_manticore_exit,
    .workers     = 2,
    .config_map  = config_map,

    /* for testing */
    .test_formatter.callback = cb_manticore_format_test,

    .event_type  = FLB_OUTPUT_LOGS,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS
};
