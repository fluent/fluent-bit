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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "doris.h"
#include "doris_conf.h"

#include <fluent-bit/flb_callback.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <windows.h>
#endif

static inline void sync_fetch_and_add(size_t *dest, size_t value) {
#ifdef FLB_SYSTEM_WINDOWS
    #ifdef _WIN64
        InterlockedAdd64((LONG64 volatile *) dest, (LONG64) value);
    #else
        InterlockedAdd((LONG volatile *) dest, (LONG) value);
    #endif
#else
    __sync_fetch_and_add(dest, value);
#endif
}

static int cb_doris_init(struct flb_output_instance *ins,
                         struct flb_config *config, void *data)
{
    struct flb_out_doris *ctx = NULL;
    (void) data;

    ctx = flb_doris_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    return 0;
}

static int http_put(struct flb_out_doris *ctx,
                    const char *host, int port,
                    const void *body, size_t body_len,
                    const char *tag, int tag_len,
                    const char *label, int label_len,
                    const char *endpoint_type)
{
    flb_plg_debug(ctx->ins, "send to %s", endpoint_type);

    int ret;
    int out_ret = FLB_OK;
    size_t b_sent;
    void *payload_buf = NULL;
    size_t payload_size = 0;
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *key = NULL;
    struct flb_slist_entry *val = NULL;

    int i;
    int root_type;
    char *out_buf;
    size_t off = 0;
    size_t out_size;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object msg_key;
    msgpack_object msg_val;

    char address[1024] = {0};
    int len = 0;

    /* Get upstream context and connection */
    if (strcmp(host, ctx->host) == 0 && port == ctx->port) { // address in config
        u = ctx->u;
    }
    else { // redirected address
        len = snprintf(address, sizeof(address), "%s:%i", host, port);
        u = flb_hash_table_get_ptr(ctx->u_pool, address, len);
        if (!u) { // first check
            pthread_mutex_lock(&ctx->mutex); // lock
            u = flb_hash_table_get_ptr(ctx->u_pool, address, len);
            if (!u) { // second check
                u = flb_upstream_create(ctx->u->base.config,
                                        host,
                                        port,
                                        ctx->u->base.flags,
                                        ctx->u->base.tls_context);
                if (u) {
                    flb_hash_table_add(ctx->u_pool, address, len, u, 0);
                }
            }
            pthread_mutex_unlock(&ctx->mutex); // unlock
            if (!u) {
                flb_plg_error(ctx->ins, "no doris be connections available to %s:%i",
                              host, port);
                return FLB_RETRY;
            }
        }
    }
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available to %s:%i",
                      u->tcp_host, u->tcp_port);
        return FLB_RETRY;
    }

    /* Map payload */
    payload_buf = (void *) body;
    payload_size = body_len;

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_PUT, ctx->uri,
                        payload_buf, payload_size,
                        host, port,
                        NULL, 0);

    /*
     * Direct assignment of the callback context to the HTTP client context.
     * This needs to be improved through a more clean API.
     */
    c->cb_ctx = ctx->ins->callback;

    /* Append headers */
    flb_http_add_header(c, "format", 6, "json", 4);
    flb_http_add_header(c, "read_json_by_line", 17, "true", 4);
    if (strcasecmp(endpoint_type, "fe") == 0) {
        flb_http_add_header(c, "Expect", 6, "100-continue", 12);
    }
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    
    if (ctx->add_label) {
        flb_http_add_header(c, "label", 5, label, label_len);
        flb_plg_debug(ctx->ins, "add label: %s", label);
    }

    flb_config_map_foreach(head, mv, ctx->headers) {
        key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_http_add_header(c,
                            key->str, flb_sds_len(key->str),
                            val->str, flb_sds_len(val->str));
    }

    /* Basic Auth headers */
    flb_http_basic_auth(c, ctx->user, ctx->password);

    ret = flb_http_do(c, &b_sent);
    if (ret == 0) {
        if (ctx->log_request) {
            flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i\n%s\n",
                          host, port,
                          c->resp.status, c->resp.payload);
        } else {
            flb_plg_debug(ctx->ins, "%s:%i, HTTP status=%i\n%s\n",
                          host, port,
                          c->resp.status, c->resp.payload);
        }

        if (c->resp.status == 307) { // redirect
            // example: Location: http://admin:admin@127.0.0.1:8040/api/d_fb/t_fb/_stream_load?
            char* location = strstr(c->resp.data, "Location:");
            char* start = strstr(location, "@") + 1;
            char* mid = strstr(start, ":");
            char* end = strstr(mid, "/api");
            char redirect_host[1024] = {0};
            memcpy(redirect_host, start, mid - start);
            char redirect_port[10] = {0};
            memcpy(redirect_port, mid + 1, end - (mid + 1));
            
            out_ret = http_put(ctx, redirect_host, atoi(redirect_port), 
                               body, body_len, tag, tag_len, label, label_len, "be");
        }
        else if (c->resp.status == 200 && c->resp.payload_size > 0) {
            ret = flb_pack_json(c->resp.payload, c->resp.payload_size,
                                &out_buf, &out_size, &root_type, NULL);

            if (ret == -1) {
                out_ret = FLB_RETRY;
                goto parse_done;
            }
            
            msgpack_unpacked_init(&result);
            ret = msgpack_unpack_next(&result, out_buf, out_size, &off);
            if (ret != MSGPACK_UNPACK_SUCCESS) {
                out_ret = FLB_RETRY;
                goto free_buf;
            }

            root = result.data;
            if (root.type != MSGPACK_OBJECT_MAP) {
                out_ret = FLB_RETRY;
            }

            for (i = 0; i < root.via.map.size; i++) {
                msg_key = root.via.map.ptr[i].key;
                if (msg_key.type != MSGPACK_OBJECT_STR) {
                    out_ret = FLB_RETRY;
                    break;
                }

                if (msg_key.via.str.size == 6 && strncasecmp(msg_key.via.str.ptr, "Status", 6) == 0) {
                    msg_val = root.via.map.ptr[i].val;
                    if (msg_val.type != MSGPACK_OBJECT_STR) {
                        out_ret = FLB_RETRY;
                        break;
                    }

                    if (msg_val.via.str.size == 7 && strncasecmp(msg_val.via.str.ptr, "Success", 7) == 0) {
                        out_ret = FLB_OK;
                        break;
                    }
                    
                    if (msg_val.via.str.size == 15 && strncasecmp(msg_val.via.str.ptr, "Publish Timeout", 15) == 0) {
                        out_ret = FLB_OK;
                        break;
                    }
                    
                    out_ret = FLB_RETRY;
                    break;
                }
            }
free_buf:
            flb_free(out_buf);
            msgpack_unpacked_destroy(&result);
parse_done:
        }
        else {
            out_ret = FLB_RETRY;
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->host, ctx->port, ret);
        out_ret = FLB_RETRY;
    }

    /* cleanup */
    
    /*
     * If the payload buffer is different than incoming records in body, means
     * we generated a different payload and must be freed.
     */
    if (payload_buf != body) {
        flb_free(payload_buf);
    }

    /* Destroy HTTP client context */
    flb_http_client_destroy(c);

    /* Release the TCP connection */
    flb_upstream_conn_release(u_conn);

    return out_ret;
}

static int compose_payload(struct flb_out_doris *ctx,
                           const void *in_body, size_t in_size,
                           void **out_body, size_t *out_size,
                           struct flb_config *config)
{
    flb_sds_t encoded;

    *out_body = NULL;
    *out_size = 0;

    encoded = flb_pack_msgpack_to_json_format(in_body,
                                              in_size,
                                              ctx->out_format,
                                              FLB_PACK_JSON_DATE_EPOCH,
                                              ctx->date_key,
                                              config->json_escape_unicode);
    if (encoded == NULL) {
        flb_plg_error(ctx->ins, "failed to convert json");
        return FLB_ERROR;
    }
    *out_body = (void*)encoded;
    *out_size = flb_sds_len(encoded);

    if (ctx->log_request) {
        flb_plg_info(ctx->ins, "http body: %s", (char*) *out_body);
    } else {
        flb_plg_debug(ctx->ins, "http body: %s", (char*) *out_body);
    }

    return FLB_OK;
}

static void cb_doris_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    int ret = FLB_ERROR;
    struct flb_out_doris *ctx = out_context;
    void *out_body;
    size_t out_size;
    (void) i_ins;

    char label[1024] = {0};
    int len = 0;

    ret = compose_payload(ctx, event_chunk->data, event_chunk->size,
                          &out_body, &out_size, config);

    if (ret != FLB_OK) {
        if (ret == FLB_ERROR && ctx->log_progress_interval > 0) {
            sync_fetch_and_add(&ctx->reporter->failed_rows, event_chunk->total_events);
        }
        FLB_OUTPUT_RETURN(ret);
    }

    if (ctx->add_label) {
        /* {label_prefix}_{db}_{table}_{timestamp}_{uuid} */
        len = snprintf(label, sizeof(label), "%s_%s_%s_%lu_", ctx->label_prefix, ctx->database, ctx->table, cfl_time_now() / 1000000000L);
        flb_utils_uuid_v4_gen(label + len);
        len += 36;
    }

    ret = http_put(ctx, ctx->host, ctx->port, out_body, out_size,
                   event_chunk->tag, flb_sds_len(event_chunk->tag), label, len, ctx->endpoint_type);
    flb_sds_destroy(out_body);

    if (ret == FLB_OK && ctx->log_progress_interval > 0) {
        sync_fetch_and_add(&ctx->reporter->total_bytes, out_size);
        sync_fetch_and_add(&ctx->reporter->total_rows, event_chunk->total_events);
    } else if (ret == FLB_ERROR && ctx->log_progress_interval > 0) {
        sync_fetch_and_add(&ctx->reporter->failed_rows, event_chunk->total_events);
    }
    FLB_OUTPUT_RETURN(ret);
}

static int cb_doris_exit(void *data, struct flb_config *config)
{
    struct flb_out_doris *ctx = data;

    flb_doris_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    // endpoint_type
    {
     FLB_CONFIG_MAP_STR, "endpoint_type", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_doris, endpoint_type),
     "Set endpoint type: 'fe' (frontend) or 'be' (backend)"
    },
    // user
    {
     FLB_CONFIG_MAP_STR, "user", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_doris, user),
     "Set HTTP auth user"
    },
    // password
    {
     FLB_CONFIG_MAP_STR, "password", "",
     0, FLB_TRUE, offsetof(struct flb_out_doris, password),
     "Set HTTP auth password"
    },
    // database
    {
     FLB_CONFIG_MAP_STR, "database", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_doris, database),
     "Set database"
    },
    // table
    {
     FLB_CONFIG_MAP_STR, "table", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_doris, table),
     "Set table"
    },
    // label_prefix
    {
     FLB_CONFIG_MAP_STR, "label_prefix", "fluentbit",
     0, FLB_TRUE, offsetof(struct flb_out_doris, label_prefix),
     "Set label prefix"
    },
    // time_key
    {
     FLB_CONFIG_MAP_STR, "time_key", "date",
     0, FLB_TRUE, offsetof(struct flb_out_doris, time_key),
     "Specify the name of the date field in output"
    },
    // header
    {
     FLB_CONFIG_MAP_SLIST_1, "header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_out_doris, headers),
     "Add a doris stream load header key/value pair. Multiple headers can be set"
    },
    // log_request
    {
     FLB_CONFIG_MAP_BOOL, "log_request", "true",
     0, FLB_TRUE, offsetof(struct flb_out_doris, log_request),
     "Specify if the doris stream load request and response should be logged or not"
    },
    // log_progress_interval
    {
     FLB_CONFIG_MAP_INT, "log_progress_interval", "10",
     0, FLB_TRUE, offsetof(struct flb_out_doris, log_progress_interval),
     "Specify the interval in seconds to log the progress of the doris stream load"
    },

    /* EOF */
    {0}
};

static int cb_doris_format_test(struct flb_config *config,
                                struct flb_input_instance *ins,
                                void *plugin_context,
                                void *flush_ctx,
                                int event_type,
                                const char *tag, int tag_len,
                                const void *data, size_t bytes,
                                void **out_data, size_t *out_size)
{
    struct flb_out_doris *ctx = plugin_context;
    int ret;

    ret = compose_payload(ctx, data, bytes, out_data, out_size, config);
    if (ret != FLB_OK) {
        flb_error("ret=%d", ret);
        return -1;
    }
    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_doris_plugin = {
    .name        = "doris",
    .description = "Doris Output",
    .cb_init     = cb_doris_init,
    .cb_pre_run  = NULL,
    .cb_flush    = cb_doris_flush,
    .cb_exit     = cb_doris_exit,
    .config_map  = config_map,

    /* for testing */
    .test_formatter.callback = cb_doris_format_test,

    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .workers     = 2
};