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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_compat.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <msgpack.h>

#include "nginx.h"

/**
 * parse the output of the nginx stub_status module.
 *
 * An example:
 *     Active connections: 1
 *     server accepts handled requests
 *      10 10 10
 *     Reading: 0 Writing: 1 Waiting: 0
 *
 * Would result in:
 *    struct nginx_status = {
 *        active = 1,
 *        reading = 0,
 *        writing = 1,
 *        waiting = 0
 *        accepts = 10,
 *        handled = 10,
 *        requests = 10
 *}
 */
static int nginx_parse_stub_status(flb_sds_t buf, struct nginx_status *status)
{
    struct mk_list *llines;
    struct mk_list *head = NULL;
    char *lines[4];
    int line = 0;
    int rc;
    struct flb_split_entry *cur = NULL;


    llines = flb_utils_split(buf, '\n', 4);
    if (llines == NULL) {
        return -1;
    }

    mk_list_foreach(head, llines) {
        cur = mk_list_entry(head, struct flb_split_entry, _head);
        lines[line] = cur->value;
        line++;
    }
    if (line < 4) {
        goto error;
    }

    rc = sscanf(lines[0], "Active connections: %" PRIu64 " \n", &status->active);
    if (rc != 1) {
        goto error;
    }
    rc = sscanf(lines[2], " %" PRIu64 " %" PRIu64 " %" PRIu64 " \n",
           &status->accepts, &status->handled, &status->requests);
    if (rc != 3) {
        goto error;
    }
    rc = sscanf(lines[3], "Reading: %" PRIu64 " Writing: %" PRIu64 " Waiting: %" PRIu64 " \n",
            &status->reading, &status->writing, &status->waiting);
    if (rc != 3) {
        goto error;
    }

    flb_utils_split_free(llines);
    return 0;
error:
    flb_utils_split_free(llines);
    return -1;
}

/**
 * Callback function to gather statistics from the nginx
 * status module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int Always returns success
 */
static int nginx_collect_stub_status(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    struct nginx_ctx *ctx = (struct nginx_ctx *)in_context;
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    struct nginx_status status;
    flb_sds_t data;

    size_t b_sent;
    int ret = -1;
    int rc = -1;
    uint64_t ts = cfl_time_now();


    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto conn_error;
    }

    client = flb_http_client(u_conn, FLB_HTTP_GET, ctx->status_url,
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: %d", client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    /* copy and NULL terminate the payload */
    data = flb_sds_create_size(client->resp.payload_size + 1);
    if (!data) {
        goto http_error;
    }
    memcpy(data, client->resp.payload, client->resp.payload_size);
    data[client->resp.payload_size] = '\0';

    /* work directly on the data here ... */
    if (nginx_parse_stub_status(data, &status) == -1) {
        flb_plg_error(ins, "unable to parse stub status response");
        goto status_error;
    }

    rc = 0;

    cmt_counter_set(ctx->connections_accepted, ts, (double)status.accepts, 0, NULL);
    cmt_gauge_set(ctx->connections_active, ts, (double)status.active, 0, NULL);
    cmt_counter_set(ctx->connections_handled, ts, (double)status.handled, 0, NULL);

    cmt_gauge_set(ctx->connections_reading, ts, (double)status.reading, 0, NULL);
    cmt_gauge_set(ctx->connections_writing, ts, (double)status.writing, 0, NULL);
    cmt_gauge_set(ctx->connections_waiting, ts, (double)status.waiting, 0, NULL);

    cmt_counter_set(ctx->connections_total, ts, (double)status.requests, 0, NULL);

status_error:
    flb_sds_destroy(data);
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    if (rc == 0 && ctx->is_up == FLB_FALSE) {
        cmt_gauge_set(ctx->connection_up, ts, 1.0, 0, NULL);
        ctx->is_up = FLB_TRUE;
    }
    else if (rc != 0 && ctx->is_up == FLB_TRUE) {
        cmt_gauge_set(ctx->connection_up, ts, 0.0, 0, NULL);
        ctx->is_up = FLB_FALSE;
    }
    ret = flb_input_metrics_append(ins, NULL, 0, ctx->cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }

    return rc;
}


int process_connections(void *ctx, uint64_t ts, char *buf, size_t size)
{
    struct nginx_plus_connections *plus = (struct nginx_plus_connections *)ctx;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object_kv *cur;
    msgpack_object_str *key;
    int i = 0;


    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            for (i = 0; i < result.data.via.map.size; i++) {
                
                cur = &result.data.via.map.ptr[i];
                key = &cur->key.via.str;

                if (strncmp(key->ptr, "accepted", key->size) == 0) {
                    cmt_counter_set(plus->connections_accepted, ts,
                                    (double)cur->val.via.i64, 0, NULL);
                }
                else if (strncmp(key->ptr, "dropped", key->size) == 0) {
                    cmt_counter_set(plus->connections_dropped, ts,
                                    (double)cur->val.via.i64, 0, NULL);
                }
                else if (strncmp(key->ptr, "active", key->size) == 0) {
                    cmt_counter_set(plus->connections_active, ts,
                                    (double)cur->val.via.i64, 0, NULL);
                }
                else if (strncmp(key->ptr, "idle", key->size) == 0) {
                    cmt_counter_set(plus->connections_idle, ts,
                                    (double)cur->val.via.i64, 0, NULL);
                }
            }
            break;
        }
    }
    msgpack_unpacked_destroy(&result);
    return 0;
}

int process_ssl(void *ctx, uint64_t ts, char *buf, size_t size)
{
    struct nginx_plus_ssl *plus = (struct nginx_plus_ssl *)ctx;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object_kv *cur;
    msgpack_object_str *key;
    int i = 0;


    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            for (i = 0; i < result.data.via.map.size; i++) {
                cur = &result.data.via.map.ptr[i];
                key = &cur->key.via.str;
                if (strncmp(key->ptr, "handshakes", key->size) == 0) {
                    cmt_counter_set(plus->handshakes, ts,
                                    (double)cur->val.via.i64, 0, NULL);
                }
                else if (strncmp(key->ptr, "handshakes_failed", key->size) == 0) {
                    cmt_counter_set(plus->handshakes_failed, ts,
                                    (double)cur->val.via.i64, 0, NULL);
                }
                else if (strncmp(key->ptr, "session_reuses", key->size) == 0) {
                    cmt_counter_set(plus->session_reuses, ts,
                                    (double)cur->val.via.i64, 0, NULL);
                }
            }
            break;
        }
    }
    msgpack_unpacked_destroy(&result);
    return 0;
}

int process_http_requests(void *ctx, uint64_t ts, char *buf, size_t size)
{
    struct nginx_plus_http_requests *plus = (struct nginx_plus_http_requests *)ctx;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object_kv *cur;
    msgpack_object_str *key;
    int i = 0;


    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            for (i = 0; i < result.data.via.map.size; i++) {
                cur = &result.data.via.map.ptr[i];
                key = &cur->key.via.str;
                if (strncmp(key->ptr, "total", key->size) == 0) {
                    cmt_counter_set(plus->total, ts,
                                    (double)cur->val.via.i64, 0, NULL);
                }
                else if (strncmp(key->ptr, "current", key->size) == 0) {
                    cmt_counter_set(plus->current, ts,
                                    (double)cur->val.via.i64, 0, NULL);
                }
            }
            break;
        }
    }
    msgpack_unpacked_destroy(&result);
    return 0;
}

static ssize_t parse_payload_json(struct nginx_ctx *nginx, void *ctx, uint64_t ts,
                                  int (*process)(void *, uint64_t, char *, size_t),
                                  char *payload, size_t size)
{
    int ret;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_warn(nginx->ins, "JSON data is incomplete, skipping");
        return -1;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(nginx->ins, "invalid JSON message, skipping");
        return -1;
    }
    else if (ret == -1) {
        return -1;
    }

    /* Process the packaged JSON and return the last byte used */
    process(ctx, ts, pack, out_size);
    flb_free(pack);

    return 0;
}

/**
 * Callback function to gather statistics from the nginx
 * plus ngx_http module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int Always returns success
 */
static int nginx_collect_plus_connections(struct flb_input_instance *ins,
                         struct flb_config *config, struct nginx_ctx *ctx, uint64_t ts)
{
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    char url[1024];
    size_t b_sent;
    int ret = -1;
    int rc = -1;


    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto conn_error;
    }

    snprintf(url, sizeof(url)-1, "%s/%d/connections", ctx->status_url,
             ctx->nginx_plus_version);
    client = flb_http_client(u_conn, FLB_HTTP_GET, url,
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: %d", client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    parse_payload_json(ctx, ctx->plus_connections, ts, process_connections,
                       client->resp.payload, client->resp.payload_size);

    rc = 0;
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    return rc;
}

/**
 * Callback function to gather statistics from the nginx
 * plus ngx_http module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int Always returns success
 */
static int nginx_collect_plus_ssl(struct flb_input_instance *ins,
                         struct flb_config *config, struct nginx_ctx *ctx, uint64_t ts)
{
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    char url[1024];
    size_t b_sent;
    int ret = -1;
    int rc = -1;


    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto conn_error;
    }

    snprintf(url, sizeof(url)-1, "%s/%d/ssl", ctx->status_url, ctx->nginx_plus_version);
    client = flb_http_client(u_conn, FLB_HTTP_GET, url,
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: %d", client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    parse_payload_json(ctx, ctx->plus_ssl, ts, process_ssl,
                       client->resp.payload, client->resp.payload_size);

    rc = 0;
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    return rc;
}

/**
 * Callback function to gather statistics from the nginx
 * plus ngx_http module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int Always returns success
 */
static int nginx_collect_plus_http_requests(struct flb_input_instance *ins,
                         struct flb_config *config, struct nginx_ctx *ctx, uint64_t ts)
{
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    char url[1024];
    size_t b_sent;
    int ret = -1;
    int rc = -1;


    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto conn_error;
    }

    snprintf(url, sizeof(url)-1, "%s/%d/http/requests", ctx->status_url,
             ctx->nginx_plus_version);
    client = flb_http_client(u_conn, FLB_HTTP_GET, url,
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: %d", client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    parse_payload_json(ctx, ctx->plus_http_requests, ts, process_http_requests,
                       client->resp.payload, client->resp.payload_size);

    rc = 0;
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    return rc;
}

void *process_server_zone(struct nginx_ctx *ctx, char *zone, uint64_t ts,
                          msgpack_object_map *map)
{
    msgpack_object_kv *responses;
    msgpack_object_kv *cur;
    msgpack_object_str *key;
    int i = 0;
    int x = 0;
    char code[4] = { '0', 'x', 'x', 0};


    for (i = 0; i < map->size; i++) {
        cur = &map->ptr[i];
        key = &cur->key.via.str;
        if (strncmp(key->ptr, "processing", key->size) == 0) {
            cmt_counter_set(ctx->server_zones->processing, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(key->ptr, "requests", key->size) == 0) {
            cmt_counter_set(ctx->server_zones->requests, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(key->ptr, "discarded", key->size) == 0) {
            cmt_counter_set(ctx->server_zones->discarded, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(key->ptr, "received", key->size) == 0) {
            cmt_counter_set(ctx->server_zones->received, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(key->ptr, "sent", key->size) == 0) {
            cmt_counter_set(ctx->server_zones->sent, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(key->ptr, "responses", key->size) == 0) {
            for (x = 0; x < map->ptr[i].val.via.map.size; x++) {
                responses = &map->ptr[i].val.via.map.ptr[x];
                if (responses->key.via.str.size == 3 &&
                    responses->key.via.str.ptr[1] == 'x' &&
                    responses->key.via.str.ptr[2] == 'x') {
                    code[0] = responses->key.via.str.ptr[0];
                    cmt_counter_set(ctx->server_zones->responses, ts,
                                    (double)responses->val.via.i64,
                                    2, (char *[]){zone, code});
                }
            }
        }
    }
    return ctx;
}

void *process_location_zone(struct nginx_ctx *ctx, char *zone, uint64_t ts,
                            msgpack_object_map *map)
{
    msgpack_object_kv *responses;
    msgpack_object_str *str;
    int i = 0;
    int x = 0;
    char code[4] = { '0', 'x', 'x', 0};

    for (i = 0; i < map->size; i++) {
        
        str = &map->ptr[i].key.via.str;

        if (strncmp(str->ptr, "requests", str->size) == 0) {
            cmt_counter_set(ctx->location_zones->requests, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(str->ptr, "discarded", str->size) == 0) {
            cmt_counter_set(ctx->location_zones->discarded, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(str->ptr, "received", str->size) == 0) {
            cmt_counter_set(ctx->location_zones->received, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(str->ptr, "sent", str->size) == 0) {
            cmt_counter_set(ctx->location_zones->sent, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(str->ptr, "responses", str->size) == 0) {
            for (x = 0; x < map->ptr[i].val.via.map.size; x++) {
                responses = &map->ptr[i].val.via.map.ptr[x];
                if (responses->key.via.str.size == 3 &&
                    responses->key.via.str.ptr[1] == 'x' &&
                    responses->key.via.str.ptr[2] == 'x') {
                    code[0] = responses->key.via.str.ptr[0];
                    cmt_counter_set(ctx->location_zones->responses, ts,
                                    (double)responses->val.via.i64,
                                    2, (char *[]){zone, code});
                }
            }
        }
    }
    //msgpack_unpacked_destroy(&result);
    return ctx;
}

void *process_stream_server_zone(struct nginx_ctx *ctx, char *zone, uint64_t ts,
                                 msgpack_object_map *map)
{
    msgpack_object_kv *sessions;
    msgpack_object_str *str;
    int i = 0;
    int x = 0;
    char code[4] = { '0', 'x', 'x', 0};


    for (i = 0; i < map->size; i++) {
        
        str = &map->ptr[i].key.via.str;

        if (strncmp(str->ptr, "connections", str->size) == 0) {
            cmt_counter_set(ctx->streams->connections, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        if (strncmp(str->ptr, "processing", str->size) == 0) {
            cmt_counter_set(ctx->streams->processing, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(str->ptr, "discarded", str->size) == 0) {
            cmt_counter_set(ctx->streams->discarded, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(str->ptr, "received", str->size) == 0) {
            cmt_counter_set(ctx->streams->received, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(str->ptr, "sent", str->size) == 0) {
            cmt_counter_set(ctx->streams->sent, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){zone});
        }
        else if (strncmp(str->ptr, "sessions", str->size) == 0) {
            for (x = 0; x < map->ptr[i].val.via.map.size; x++) {
                sessions = &map->ptr[i].val.via.map.ptr[x];
                if (sessions->key.via.str.size == 3 &&
                    sessions->key.via.str.ptr[1] == 'x' &&
                    sessions->key.via.str.ptr[2] == 'x') {
                    code[0] = sessions->key.via.str.ptr[0];
                    cmt_counter_set(ctx->streams->sessions, ts,
                                    (double)sessions->val.via.i64,
                                    2, (char *[]){zone, code});
                }
            }
        }
    }
    //msgpack_unpacked_destroy(&result);
    return ctx;
}

static int process_upstream_peers(struct nginx_ctx *ctx, char *backend, uint64_t ts,
                                  msgpack_object_array *peers)
{
    int i = 0;
    int p = 0;
    int x = 0;
    msgpack_object_map *map;
    msgpack_object_kv *responses;
    msgpack_object_str *key;
    msgpack_object *kv;
    char *server;
    char code[4] = {'0', 'x', 'x', 0};


    for (i = 0; i < peers->size; i++) {
        map = &peers->ptr[i].via.map;
        for (p = 0, server = NULL; p < map->size; p++) {
            key = &map->ptr[p].key.via.str;
            kv = &map->ptr[p].val;
            if (strncmp(key->ptr, "server", key->size) == 0) {
                server = flb_calloc(1, kv->via.str.size+1);
                memcpy(server, kv->via.str.ptr, kv->via.str.size);
                break;
            }
        }
        if (server == NULL) {
            flb_plg_warn(ctx->ins, "no server for upstream");
            continue;
        }
        for (p = 0; p < map->size; p++) {
            key = &map->ptr[p].key.via.str;
            // initialize to zero for now to respond
            // how the official exporter does...
            cmt_gauge_set(ctx->upstreams->limit, ts, (double)0.0, 2,
                          (char *[]){backend, server});
            cmt_gauge_set(ctx->upstreams->header_time, ts, (double)0.0, 2,
                          (char *[]){backend, server});
            cmt_gauge_set(ctx->upstreams->response_time, ts, (double)0.0, 2, 
                          (char *[]){backend, server});

            if (strncmp(key->ptr, "active", key->size) == 0) {
                cmt_gauge_set(ctx->upstreams->active, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "fails", key->size) == 0) {
                cmt_counter_set(ctx->upstreams->fails, ts,
                                (double)map->ptr[p].val.via.i64, 2,
                                (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "header_time", key->size) == 0) {
                cmt_gauge_set(ctx->upstreams->header_time, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "limit", key->size) == 0) {
                cmt_gauge_set(ctx->upstreams->limit, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "received", key->size) == 0) {
                cmt_counter_set(ctx->upstreams->received, ts,
                                (double)map->ptr[p].val.via.i64, 2, 
                                (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "requests", key->size) == 0) {
                cmt_counter_set(ctx->upstreams->requests, ts,
                                (double)map->ptr[p].val.via.i64, 2,
                                (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "responses", key->size) == 0) {
                for (x = 0; x < map->ptr[p].val.via.map.size; x++) {
                    responses = &map->ptr[p].val.via.map.ptr[x];
                    if (responses->key.via.str.size == 3 &&
                        responses->key.via.str.ptr[1] == 'x' &&
                        responses->key.via.str.ptr[2] == 'x') {
                        code[0] = responses->key.via.str.ptr[0];
                        cmt_counter_set(ctx->upstreams->responses, ts,
                                        (double)responses->val.via.i64,
                                        3, (char *[]){backend, server, code});
                    }
                }
            }
            else if (strncmp(key->ptr, "response_time", key->size) == 0) {
                cmt_gauge_set(ctx->upstreams->response_time, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "sent", key->size) == 0) {
                cmt_counter_set(ctx->upstreams->sent, ts,
                                (double)map->ptr[p].val.via.i64, 2,
                                (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "state", key->size) == 0) {
                cmt_gauge_set(ctx->upstreams->state, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "unavail", key->size) == 0) {
                cmt_counter_set(ctx->upstreams->unavail, ts,
                                (double)map->ptr[p].val.via.i64, 2,
                                (char *[]){backend, server});
            }
        }
        flb_free(server);
    }
    return 0;
}

void *process_upstreams(struct nginx_ctx *ctx, char *backend, uint64_t ts,
                        msgpack_object_map *map)
{
    int i = 0;
    msgpack_object_str *key;

    for (i = 0; i < map->size; i++) {
        key = &map->ptr[i].key.via.str;
        if (strncmp(key->ptr, "keepalives", key->size) == 0) {
            cmt_gauge_set(ctx->upstreams->keepalives, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){backend});
        }
        else if (strncmp(key->ptr, "zombies", key->size) == 0) {
            cmt_gauge_set(ctx->upstreams->zombies, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){backend});
        }
        // go into the peer...
        else if (strncmp(key->ptr, "peers", key->size) == 0) {
            process_upstream_peers(ctx, backend, ts, &map->ptr[i].val.via.array);
        }
    }
    //msgpack_unpacked_destroy(&result);
    return ctx;
}

static int process_stream_upstream_peers(struct nginx_ctx *ctx, char *backend,
                                         uint64_t ts, msgpack_object_array *peers)
{
    int i = 0;
    int p = 0;
    msgpack_object_map *map;
    msgpack_object_str *key;
    char *server;


    for (i = 0; i < peers->size; i++) {
        map = &peers->ptr[i].via.map;
        for (p = 0, server = NULL; p < map->size; p++) {
            key = &map->ptr[p].key.via.str;
            if (strncmp(key->ptr, "server", key->size) == 0) {
                server = flb_calloc(1, map->ptr[p].val.via.str.size+1);
                memcpy(server, map->ptr[p].val.via.str.ptr, map->ptr[p].val.via.str.size);
                break;
            }
        }
        if (server == NULL) {
            flb_plg_warn(ctx->ins, "no server for stream upstream");
            continue;
        }
        for (p = 0; p < map->size; p++) {
            // initialize to zero for now to respond
            // how the official exporter does...
            cmt_gauge_set(ctx->stream_upstreams->limit, ts, (double)0.0, 2,
                          (char *[]){backend, server});
            cmt_gauge_set(ctx->stream_upstreams->response_time, ts, (double)0.0, 2,
                          (char *[]){backend, server});
            cmt_gauge_set(ctx->stream_upstreams->connect_time, ts, (double)0.0, 2,
                          (char *[]){backend, server});
            cmt_gauge_set(ctx->stream_upstreams->first_byte_time, ts, (double)0.0, 2,
                          (char *[]){backend, server});
            
            key = &map->ptr[p].key.via.str;
            if (strncmp(key->ptr, "active", key->size) == 0) {
                cmt_gauge_set(ctx->stream_upstreams->active, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "fails", key->size) == 0) {
                cmt_counter_set(ctx->stream_upstreams->fails, ts,
                                (double)map->ptr[p].val.via.i64, 2,
                                (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "limit", key->size) == 0) {
                cmt_gauge_set(ctx->stream_upstreams->limit, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "received", key->size) == 0) {
                cmt_counter_set(ctx->stream_upstreams->received, ts,
                                (double)map->ptr[p].val.via.i64, 2,
                                (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "connect_time", key->size) == 0) {
                cmt_gauge_set(ctx->stream_upstreams->connect_time, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "first_byte_time", key->size) == 0) {
                cmt_gauge_set(ctx->stream_upstreams->first_byte_time, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "connections", key->size) == 0) {
                cmt_counter_set(ctx->stream_upstreams->connections, ts,
                                (double)map->ptr[p].val.via.i64, 2,
                                (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "response_time", key->size) == 0) {
                cmt_gauge_set(ctx->stream_upstreams->response_time, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "sent", key->size) == 0) {
                cmt_counter_set(ctx->stream_upstreams->sent, ts,
                                (double)map->ptr[p].val.via.i64, 2,
                                (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "state", key->size) == 0) {
                cmt_gauge_set(ctx->stream_upstreams->state, ts,
                              (double)map->ptr[p].val.via.i64, 2,
                              (char *[]){backend, server});
            }
            else if (strncmp(key->ptr, "unavail", key->size) == 0) {
                cmt_counter_set(ctx->stream_upstreams->unavail, ts,
                                (double)map->ptr[p].val.via.i64, 2,
                                (char *[]){backend, server});
            }
        }
        flb_free(server);
    }
    return 0;
}

void *process_stream_upstreams(struct nginx_ctx *ctx, char *backend, uint64_t ts,
                               msgpack_object_map *map)
{
    int i = 0;
    msgpack_object_str *key;

    for (i = 0; i < map->size; i++) {
        key = &map->ptr[i].key.via.str;
        if (strncmp(key->ptr, "zombies", key->size) == 0) {
            cmt_gauge_set(ctx->stream_upstreams->zombies, ts,
                            (double)map->ptr[i].val.via.i64, 1, (char *[]){backend});
        }
        // go into the peer...
        else if (strncmp(key->ptr, "peers", key->size) == 0) {
            process_stream_upstream_peers(ctx, backend, ts, &map->ptr[i].val.via.array);
        }
    }
    //msgpack_unpacked_destroy(&result);
    return ctx;
}

static ssize_t parse_payload_json_table(struct nginx_ctx *ctx, int64_t ts,
                                        void *(*process)(struct nginx_ctx *, char *,
                                                         uint64_t, msgpack_object_map *),
                                        char *payload, size_t size)
{
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object_str *name;
    int i = 0;
    int ret;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;
    char *zone;

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size, &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_warn(ctx->ins, "JSON data is incomplete, skipping");
        return -1;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(ctx->ins, "invalid JSON message, skipping");
        return -1;
    }
    else if (ret == -1) {
        return -1;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, out_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            for (i = 0; i < result.data.via.map.size; i++) {
                name = &result.data.via.map.ptr[i].key.via.str;
                zone = flb_calloc(1, name->size+1);
                memcpy(zone, name->ptr, name->size);
                process(ctx, zone, ts, &result.data.via.map.ptr[i].val.via.map);
                flb_free(zone);
            }
        } else {
            msgpack_object_print(stdout, result.data);
        }
    }

    flb_free(pack);
    return 0;
}

/**
 * Callback function to gather statistics from the nginx
 * plus ngx_http module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int Always returns success
 */
static int nginx_collect_plus_server_zones(struct flb_input_instance *ins,
                         struct flb_config *config, struct nginx_ctx *ctx, uint64_t ts)
{
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    char url[1024];
    size_t b_sent;
    int ret = -1;
    int rc = -1;


    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto conn_error;
    }

    snprintf(url, sizeof(url)-1, "%s/%d/http/server_zones", ctx->status_url,
             ctx->nginx_plus_version);
    client = flb_http_client(u_conn, FLB_HTTP_GET, url,
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: %d", client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    parse_payload_json_table(ctx, ts, process_server_zone,
                       client->resp.payload, client->resp.payload_size);
    rc = 0;
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    return rc;
}

/**
 * Callback function to gather statistics from the nginx
 * plus ngx_http module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int Always returns success
 */
static int nginx_collect_plus_location_zones(struct flb_input_instance *ins,
                         struct flb_config *config, struct nginx_ctx *ctx, uint64_t ts)
{
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    char url[1024];
    size_t b_sent;
    int ret = -1;
    int rc = -1;


    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto conn_error;
    }

    snprintf(url, sizeof(url)-1, "%s/%d/http/location_zones", ctx->status_url,
             ctx->nginx_plus_version);
    client = flb_http_client(u_conn, FLB_HTTP_GET, url,
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: [%s] %d", url, client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    parse_payload_json_table(ctx, ts, process_location_zone,
                       client->resp.payload, client->resp.payload_size);
    rc = 0;
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    return rc;
}

/**
 * Callback function to gather statistics from the nginx
 * plus ngx_http module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int Always returns success
 */
static int nginx_collect_plus_upstreams(struct flb_input_instance *ins,
                         struct flb_config *config, struct nginx_ctx *ctx, uint64_t ts)
{
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    char url[1024];
    size_t b_sent;
    int ret = -1;
    int rc = -1;


    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto conn_error;
    }

    snprintf(url, sizeof(url)-1, "%s/%d/http/upstreams", ctx->status_url,
             ctx->nginx_plus_version);
    client = flb_http_client(u_conn, FLB_HTTP_GET, url,
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: [%s] %d", url, client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    parse_payload_json_table(ctx, ts, process_upstreams,
                       client->resp.payload, client->resp.payload_size);
    rc = 0;
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    return rc;
}

/**
 * Callback function to gather statistics from the nginx
 * plus ngx_http module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int Always returns success
 */
static int nginx_collect_plus_stream_server_zones(struct flb_input_instance *ins,
                         struct flb_config *config, struct nginx_ctx *ctx, uint64_t ts)
{
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    char url[1024];
    size_t b_sent;
    int ret = -1;
    int rc = -1;


    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto conn_error;
    }

    snprintf(url, sizeof(url)-1, "%s/%d/stream/server_zones", ctx->status_url,
             ctx->nginx_plus_version);
    client = flb_http_client(u_conn, FLB_HTTP_GET, url,
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: [%s] %d", url, client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    parse_payload_json_table(ctx, ts, process_stream_server_zone,
                       client->resp.payload, client->resp.payload_size);
    rc = 0;
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    return rc;
}

/**
 * Callback function to gather statistics from the nginx
 * plus ngx_http module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int Always returns success
 */
static int nginx_collect_plus_stream_upstreams(struct flb_input_instance *ins,
                                               struct flb_config *config,
                                               struct nginx_ctx *ctx, uint64_t ts)
{
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    char url[1024];
    size_t b_sent;
    int ret = -1;
    int rc = -1;


    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto conn_error;
    }

    snprintf(url, sizeof(url)-1, "%s/%d/stream/upstreams", ctx->status_url,
             ctx->nginx_plus_version);
    client = flb_http_client(u_conn, FLB_HTTP_GET, url,
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: [%s] %d", url, client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    parse_payload_json_table(ctx, ts, process_stream_upstreams,
                       client->resp.payload, client->resp.payload_size);
    rc = 0;
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    return rc;
}

/**
 * Get the current highest REST API version
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int highest version if > 0, error otherwise.
 */
static int nginx_plus_get_version(struct flb_input_instance *ins,
                                  struct flb_config *config,
                                  struct nginx_ctx *ctx)
{
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    char url[1024];
    size_t b_sent;
    int rc = -1;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;
    size_t off = 0;
    msgpack_unpacked result;
    int maxversion = 1;
    int i = 0;


    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto conn_error;
    }

    snprintf(url, sizeof(url)-1, "%s/", ctx->status_url);
    client = flb_http_client(u_conn, FLB_HTTP_GET, url,
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    rc = flb_http_do(client, &b_sent);
    if (rc != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: [%s] %d", url, client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    rc = flb_pack_json_state(client->resp.payload, client->resp.payload_size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (rc == FLB_ERR_JSON_PART) {
        flb_plg_warn(ins, "JSON data is incomplete, skipping");
        goto json_error;
    }
    else if (rc == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(ins, "invalid JSON message, skipping");
        goto json_error;
    }
    else if (rc == -1) {
        flb_plg_error(ins, "unable to parse JSON response");
        goto json_error;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, out_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            for (i = 0; i < result.data.via.array.size; i++) {
                if (result.data.via.array.ptr[i].via.i64 > maxversion) {
                    maxversion = result.data.via.array.ptr[i].via.i64;
                }
            }
        } else {
            flb_plg_error(ins, "NOT AN ARRAY");
            goto rest_error;
        }
    }

rest_error:
    msgpack_unpacked_destroy(&result);
json_error:
    flb_free(pack);
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    return maxversion;
}


/**
 * Callback function to gather statistics from the nginx
 * plus ngx_http module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to nginx_ctx
 *
 * @return int Always returns success
 */
static int nginx_collect_plus(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int version = -1;
    struct nginx_ctx *ctx = (struct nginx_ctx *)in_context;
    int rc = -1;
    int ret = -1;
    uint64_t ts = cfl_time_now();


    version = nginx_plus_get_version(ins, config, in_context);
    if (version <= 0) {
        flb_plg_error(ins, "bad NGINX plus REST API version = %d", version);
        goto error;
    }
    ctx->nginx_plus_version = version;

    rc = nginx_collect_plus_connections(ins, config, ctx, ts);
    if (rc != 0) {
        goto error;
    }
    rc = nginx_collect_plus_ssl(ins, config, ctx, ts);
    if (rc != 0) {
        goto error;
    }
    rc = nginx_collect_plus_http_requests(ins, config, ctx, ts);
    if (rc != 0) {
        goto error;
    }
    rc = nginx_collect_plus_server_zones(ins, config, ctx, ts);
    if (rc != 0) {
        goto error;
    }

    if (ctx->nginx_plus_version >= 5) {
        rc = nginx_collect_plus_location_zones(ins, config, ctx, ts);
        if (rc != 0) {
            goto error;
        }
    }

    rc = nginx_collect_plus_upstreams(ins, config, ctx, ts);
    if (rc != 0) {
        goto error;
    }
    rc = nginx_collect_plus_stream_server_zones(ins, config, ctx, ts);
    if (rc != 0) {
        goto error;
    }
    rc = nginx_collect_plus_stream_upstreams(ins, config, ctx, ts);
    if (rc != 0) {
        goto error;
    }
error:
    if (rc == 0) {
        cmt_gauge_set(ctx->connection_up, ts, (double)1.0, 0, NULL);
    } else {
        cmt_gauge_set(ctx->connection_up, ts, (double)0.0, 0, NULL);
    }
    ret = flb_input_metrics_append(ins, NULL, 0, ctx->cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }
    return rc;
}

/**
 * Function to initialize nginx metrics plugin.
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 *
 * @return struct nginx_ctx_init* Pointer to the plugin's
 *         structure on success, NULL on failure.
 */
struct nginx_ctx *nginx_ctx_init(struct flb_input_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    int upstream_flags;
    struct nginx_ctx *ctx;
    struct flb_upstream *upstream;

    if (ins->host.name == NULL) {
        ins->host.name = flb_sds_create("localhost");
    }
    if (ins->host.port == 0) {
        ins->host.port = 80;
    }

    ctx = flb_calloc(1, sizeof(struct nginx_ctx));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->is_up = FLB_FALSE;

    ctx->ins = ins;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    ctx->cmt = cmt_create();
    if (!ctx->cmt) {
        flb_plg_error(ins, "could not initialize CMetrics");
        flb_free(ctx);
        return NULL;
    }

    upstream_flags = FLB_IO_TCP;

    if (ins->use_tls) {
        upstream_flags |= FLB_IO_TLS;
    }

    upstream = flb_upstream_create(config, ins->host.name, ins->host.port,
                                   upstream_flags, ins->tls);

    if (!upstream) {
        flb_plg_error(ins, "upstream initialization error");
        cmt_destroy(ctx->cmt);
        flb_free(ctx);
        return NULL;
    }
    ctx->upstream = upstream;

    return ctx;
}

static int nginx_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int rc;
    struct nginx_ctx *ctx = (struct nginx_ctx *)in_context;
    if (ctx->is_nginx_plus == FLB_TRUE) {
        rc = nginx_collect_plus(ins, config, in_context);
    } else {
        rc = nginx_collect_stub_status(ins, config, in_context);
    }
    FLB_INPUT_RETURN(rc);
}

static int nginx_ctx_destroy(struct nginx_ctx *ctx);
/**
 * Callback function to initialize nginx metrics plugin
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 * @param data    Unused
 *
 * @return int 0 on success, -1 on failure
 */
static int nginx_init(struct flb_input_instance *ins,
                      struct flb_config *config, void *data)
{
    struct nginx_ctx *ctx = NULL;
    struct cmt_counter *c;
    struct cmt_gauge *g;
    int ret = -1;

    /* Allocate space for the configuration */
    ctx = nginx_ctx_init(ins, config);
    if (!ctx) {
        return -1;
    }


    flb_input_set_context(ins, ctx);

    if (ctx->is_nginx_plus == FLB_FALSE) {
        /* These metrics follow the same format as those define here:
         * https://github.com/nginxinc/nginx-prometheus-exporter#metrics-for-nginx-oss
         */
        ctx->connections_accepted = cmt_counter_create(ctx->cmt, "nginx", "connections",
                                                       "accepted",
                                                       "Accepted client connections", 0, 
                                                       NULL);
        if (ctx->connections_accepted == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(ctx->connections_accepted);

        ctx->connections_active = cmt_gauge_create(ctx->cmt, "nginx", "connections",
                                                   "active", "active client connections", 
                                                   0, NULL);
        if (ctx->connections_active == NULL) {
            goto nginx_init_end;
        }

        ctx->connections_handled = cmt_counter_create(ctx->cmt, "nginx", "connections",
                                                      "handled",
                                                      "Handled client connections", 0, 
                                                      NULL);
        if (ctx->connections_handled == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(ctx->connections_handled);

        ctx->connections_reading = cmt_gauge_create(ctx->cmt, "nginx", "connections",
                                                    "reading", 
                                                    "reading client connections",
                                                    0, NULL);
        if (ctx->connections_reading == NULL) {
            goto nginx_init_end;
        }

        ctx->connections_writing = cmt_gauge_create(ctx->cmt, "nginx", "connections",
                                                    "writing", 
                                                    "writing client connections",
                                                    0, NULL);
        if (ctx->connections_writing == NULL) {
            goto nginx_init_end;
        }

        ctx->connections_waiting = cmt_gauge_create(ctx->cmt, "nginx", "connections",
                                                    "waiting",
                                                    "waiting client connections",
                                                    0, NULL);
        if (ctx->connections_waiting == NULL) {
            goto nginx_init_end;
        }

        ctx->connections_total = cmt_counter_create(ctx->cmt, "nginx", "http",
                                                    "requests_total", 
                                                    "Total http requests", 0, NULL);
        if (ctx->connections_total == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(ctx->connections_total);

        ctx->connection_up = cmt_gauge_create(ctx->cmt, "nginx", "", "up",
                                              "Shows the status of the last metric "
                                              "scrape: 1 for a successful scrape and "
                                              "0 for a failed one",
                                              0, NULL);
    } else {
        flb_plg_info(ins, "nginx-plus mode on");

        ctx->plus_connections = flb_calloc(1, sizeof(struct nginx_plus_connections));
        ctx->plus_ssl = flb_calloc(1, sizeof(struct nginx_plus_ssl));
        ctx->plus_http_requests = flb_calloc(1, sizeof(struct nginx_plus_http_requests));
        ctx->server_zones = flb_calloc(1, sizeof(struct nginx_plus_server_zones));
        ctx->location_zones = flb_calloc(1, sizeof(struct nginx_plus_location_zones));
        ctx->upstreams = flb_calloc(1, sizeof(struct nginx_plus_upstreams));
        ctx->streams = flb_calloc(1, sizeof(struct nginx_plus_streams));
        ctx->stream_upstreams = flb_calloc(1, sizeof(struct nginx_plus_stream_upstreams));

        g = cmt_gauge_create(ctx->cmt, "nginxplus", "", "up",
                             "Shows the status of the last metric scrape: "
                             "1 for a successful scrape and 0 for a failed "
                             "one", 0, NULL);
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->connection_up = g;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus", "connections", "accepted",
                               "NGINX Plus Total Connections",
                               0, NULL);
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->plus_connections->connections_accepted = c;


        c = cmt_counter_create(ctx->cmt,
                               "nginxplus", "connections", "dropped",
                               "NGINX Plus Total Connections",
                               0, NULL);
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->plus_connections->connections_dropped = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus", "connections", "active",
                               "NGINX Plus Total Connections",
                               0, NULL);
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->plus_connections->connections_active = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus", "connections", "idle",
                               "NGINX Plus Total Connections",
                               0, NULL);
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->plus_connections->connections_idle = c;
        
        c = cmt_counter_create(ctx->cmt,
                               "nginxplus", "ssl", "handshakes",
                               "NGINX Plus Total Connections",
                               0, NULL);
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->plus_ssl->handshakes = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus", "ssl", "handshakes_failed",
                               "NGINX Plus Total Connections",
                               0, NULL);
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->plus_ssl->handshakes_failed = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus", "ssl", "session_reuses",
                               "NGINX Plus Total Connections",
                               0, NULL);
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->plus_ssl->session_reuses = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus", "http_requests", "total",
                               "NGINX Plus Total Connections",
                               0, NULL);
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->plus_http_requests->total = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus", "http_requests", "current",
                               "NGINX Plus Total Connections",
                              0, NULL);
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->plus_http_requests->current = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "server_zone",
                               "discarded",
                               "NGINX Server Zone discarded",
                               1, (char *[]){"server_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->server_zones->discarded = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "server_zone",
                               "processing",
                               "NGINX Server Zone processing",
                               1, (char *[]){"server_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->server_zones->processing = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "server_zone",
                               "received",
                               "NGINX Server Zone received",
                               1, (char *[]){"server_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->server_zones->received = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "server_zone",
                               "requests",
                               "NGINX Server Zone requests",
                               1, (char *[]){"server_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->server_zones->requests = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "server_zone",
                               "responses",
                               "NGINX Server Zone responses",
                               2, (char *[]){"server_zone", "code"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->server_zones->responses = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "server_zone",
                               "sent",
                               "NGINX Server Zone sent",
                               1, (char *[]){"server_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->server_zones->sent = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "server_zone",
                               "discarded",
                               "NGINX Server Zone discarded",
                               1, (char *[]){"location_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->location_zones->discarded = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "location_zone",
                               "received",
                               "NGINX Server Zone received",
                               1, (char *[]){"location_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->location_zones->received = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "location_zone",
                               "requests",
                               "NGINX Server Zone requests",
                               1, (char *[]){"location_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->location_zones->requests = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "location_zone",
                               "responses",
                               "NGINX Server Zone responses",
                               2, (char *[]){"location_zone", "code"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->location_zones->responses = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "location_zone",
                               "sent",
                               "NGINX Server Zone sent",
                               1, (char *[]){"location_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->location_zones->sent = c;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "upstream",
                             "keepalives",
                             "NGINX Upstream Keepalives",
                             1, (char *[]){"upstream"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->upstreams->keepalives = g;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "upstream",
                             "zombies",
                             "NGINX Upstream Zombies",
                             1, (char *[]){"upstream"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->upstreams->zombies = g;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "upstream_server",
                             "active",
                             "NGINX Upstream Active",
                             2, (char *[]){"upstream","server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->upstreams->active = g;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "upstream_server",
                               "fails",
                               "NGINX Upstream Fails",
                               2, (char *[]){"upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->upstreams->fails = c;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "upstream_server",
                             "header_time",
                             "NGINX Upstream Header Time",
                             2, (char *[]){"upstream","server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->upstreams->header_time = g;
        
        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "upstream_server",
                             "limit",
                             "NGINX Upstream Limit",
                             2, (char *[]){"upstream","server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->upstreams->limit = g;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "upstream_server",
                               "received",
                               "NGINX Upstream Received",
                               2, (char *[]){"upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->upstreams->received = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "upstream_server",
                               "requests",
                               "NGINX Upstream Requests",
                               2, (char *[]){"upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);                                            
        ctx->upstreams->requests = c;
        
        c = cmt_counter_create(ctx->cmt,
                              "nginxplus",
                              "upstream_server",
                              "responses",
                              "NGINX Upstream Responses",
                              3, (char *[]){"code", "upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->upstreams->responses = c;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "upstream_server",
                             "response_time",
                             "NGINX Upstream Response Time",
                             2, (char *[]){"upstream","server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->upstreams->response_time = g;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "upstream_server",
                               "sent",
                               "NGINX Upstream Sent",
                               2, (char *[]){"upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->upstreams->sent = c;

        g = cmt_gauge_create(ctx->cmt,
                                                 "nginxplus",
                                                 "upstream_server",
                                                 "state",
                                                 "NGINX Upstream State",
                                                 2, (char *[]){"upstream","server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->upstreams->state = g;

        c = cmt_counter_create(ctx->cmt,
                              "nginxplus",
                              "upstream_server",
                              "unavail",
                              "NGINX Upstream Unavailable",
                              2, (char *[]){"upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->upstreams->unavail = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "stream_server_zone",
                               "connections",
                               "NGINX Stream Server Zone connections",
                               1, (char *[]){"server_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->streams->connections = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "stream_server_zone",
                               "discarded",
                               "NGINX Stream Server Zone discarded",
                               1, (char *[]){"server_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->streams->discarded = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "stream_server_zone",
                               "processing",
                               "NGINX Stream Server Zone "
                               "processing",
                               1, (char *[]){"server_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->streams->processing = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "stream_server_zone",
                               "received",
                               "NGINX Stream Server Zone received",
                               1, (char *[]){"server_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->streams->received = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "server_zone",
                               "sent",
                               "NGINX Stream Server Zone sent",
                               1, (char *[]){"server_zone"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->streams->sent = c;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "stream_server_zone",
                               "sessions",
                               "NGINX Stream Server Zone Sessions",
                               2, (char *[]){"server_zone", "code"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->streams->sessions = c;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "stream_upstream",
                             "zombies",
                             "NGINX Upstream Zombies",
                             1, (char *[]){"upstream"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->stream_upstreams->zombies = g;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "stream_upstream_server",
                             "active",
                             "NGINX Upstream Active",
                             2, (char *[]){"upstream","server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->stream_upstreams->active = g;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "stream_upstream_server",
                               "fails",
                               "NGINX Upstream Fails",
                               2, (char *[]){"upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->stream_upstreams->fails = c;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "stream_upstream_server",
                             "limit",
                             "NGINX Upstream Limit",
                             2, (char *[]){"upstream","server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->stream_upstreams->limit = g;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "stream_upstream_server",
                               "received",
                               "NGINX Upstream Received",
                               2, (char *[]){"upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->stream_upstreams->received = c;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "stream_upstream_server",
                             "connect_time",
                             "NGINX Upstream Header Time",
                             2, (char *[]){"upstream", "server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->stream_upstreams->connect_time = g;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "stream_upstream_server",
                             "first_byte_time",
                             "NGINX Upstream Header Time",
                             2, (char *[]){"upstream", "server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->stream_upstreams->first_byte_time = g;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "stream_upstream_server",
                               "connections",
                               "NGINX Upstream Requests",
                               2, (char *[]){"upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->stream_upstreams->connections = c;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "stream_upstream_server",
                             "response_time",
                             "NGINX Upstream Response Time",
                             2, (char *[]){"upstream","server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->stream_upstreams->response_time = g;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "stream_upstream_server",
                               "sent",
                               "NGINX Upstream Sent",
                               2, (char *[]){"upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->stream_upstreams->sent = c;

        g = cmt_gauge_create(ctx->cmt,
                             "nginxplus",
                             "stream_upstream_server",
                             "state",
                             "NGINX Upstream State",
                             2, (char *[]){"upstream","server"});
        if (g == NULL) {
            goto nginx_init_end;
        }
        ctx->stream_upstreams->state = g;

        c = cmt_counter_create(ctx->cmt,
                               "nginxplus",
                               "stream_upstream_server",
                               "unavail",
                               "NGINX Upstream Unavailable",
                               2, (char *[]){"upstream","server"});
        if (c == NULL) {
            goto nginx_init_end;
        }
        cmt_counter_allow_reset(c);
        ctx->stream_upstreams->unavail = c;

    }
    ctx->coll_id = flb_input_set_collector_time(ins,
                                                nginx_collect,
                                                ctx->scrape_interval,
                                                0, config);
    ret = 0;
 nginx_init_end:
    if (ret < 0) {
        nginx_ctx_destroy(ctx);
    }

    return ret;
}


/**
 * Function to destroy nginx metrics plugin.
 *
 * @param ctx  Pointer to nginx_ctx
 *
 * @return int 0
 */
static int nginx_ctx_destroy(struct nginx_ctx *ctx)
{
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    if (ctx->cmt) {
        cmt_destroy(ctx->cmt);
    }
    if (ctx->is_nginx_plus) {
        if (ctx->plus_connections) flb_free(ctx->plus_connections);
        if (ctx->plus_ssl) flb_free(ctx->plus_ssl);
        if (ctx->plus_http_requests) flb_free(ctx->plus_http_requests); 
        if (ctx->server_zones) flb_free(ctx->server_zones);
        if (ctx->location_zones) flb_free(ctx->location_zones);
        if (ctx->upstreams) flb_free(ctx->upstreams);
        if (ctx->streams) flb_free(ctx->streams);
        if (ctx->stream_upstreams) flb_free(ctx->stream_upstreams);
    }
    flb_free(ctx);
    return 0;
}

/**
 * Callback exit function to cleanup plugin
 *
 * @param data    Pointer cast to flb_in_de_config
 * @param config  Unused
 *
 * @return int    Always returns 0
 */
static int nginx_exit(void *data, struct flb_config *config)
{
    struct nginx_ctx *ctx = (struct nginx_ctx *)data;

    if (!ctx) {
        return 0;
    }

    nginx_ctx_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "status_url", DEFAULT_STATUS_URL,
     0, FLB_TRUE, offsetof(struct nginx_ctx, status_url),
     "Define URL of stub status handler"
    },
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "5s",
     0, FLB_TRUE, offsetof(struct nginx_ctx, scrape_interval),
     "Scrape interval to collect metrics from NGINX."
    },
    {
     FLB_CONFIG_MAP_BOOL, "nginx_plus", "true",
     0, FLB_TRUE, offsetof(struct nginx_ctx, is_nginx_plus),
     "Turn on NGINX plus mode"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_nginx_exporter_metrics_plugin = {
    .name         = "nginx_metrics",
    .description  = "Nginx status metrics",
    .cb_init      = nginx_init,
    .cb_pre_run   = NULL,
    .cb_collect   = nginx_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = nginx_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET|FLB_INPUT_CORO,
};
