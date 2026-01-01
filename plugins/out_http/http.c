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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>

#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_zstd.h>

#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>

#ifdef FLB_HAVE_SIGNV4
#ifdef FLB_HAVE_AWS
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_signv4.h>
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "http.h"
#include "http_conf.h"

#include <fluent-bit/flb_callback.h>

static int cb_http_init(struct flb_output_instance *ins,
                        struct flb_config *config, void *data)
{
    struct flb_out_http *ctx = NULL;
    (void) data;

    ctx = flb_http_conf_create(ins, config);
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

static void append_headers(struct flb_http_client *c,
                           char **headers)
{
    int i;
    char *header_key;
    char *header_value;

    i = 0;
    header_key = NULL;
    header_value = NULL;
    while (*headers) {
        if (i % 2 == 0) {
            header_key = *headers;
        }
        else {
            header_value = *headers;
        }
        if (header_key && header_value) {
            flb_http_add_header(c,
                                header_key,
                                strlen(header_key),
                                header_value,
                                strlen(header_value));
            flb_free(header_key);
            flb_free(header_value);
            header_key = NULL;
            header_value = NULL;
        }
        headers++;
        i++;
    }
}

static int http_request(struct flb_out_http *ctx,
                        const void *body, size_t body_len,
                        const char *tag, int tag_len,
                        char **headers)
{
    int ret = 0;
    int out_ret = FLB_OK;
    int compressed = FLB_FALSE;
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
    flb_sds_t signature = NULL;

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available to %s:%i",
                      u->tcp_host, u->tcp_port);
        return FLB_RETRY;
    }

    /* Map payload */
    payload_buf = (void *) body;
    payload_size = body_len;

    /* Should we compress the payload ? */
    ret = 0;
    if (ctx->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress((void *) body, body_len,
                                &payload_buf, &payload_size);
        if (ret == 0) {
            compressed = FLB_TRUE;
        }
    }
    else if (ctx->compress_snappy == FLB_TRUE) {
        ret = flb_snappy_compress((void *) body, body_len,
                                  (char **) &payload_buf, &payload_size);
        if (ret == 0) {
            compressed = FLB_TRUE;
        }
    }
    else if (ctx->compress_zstd == FLB_TRUE) {
        ret = flb_zstd_compress((void *) body, body_len,
                                &payload_buf, &payload_size);
        if (ret == 0) {
            compressed = FLB_TRUE;
        }
    }

    if (ret == -1) {
        flb_plg_warn(ctx->ins, "could not compress payload, sending as it is");
        compressed = FLB_FALSE;
    }


    /* Create HTTP client context */
    c = flb_http_client(u_conn, ctx->http_method, ctx->uri,
                        payload_buf, payload_size,
                        ctx->host, ctx->port,
                        ctx->proxy, 0);

    if (c == NULL) {
        flb_plg_error(ctx->ins, "[http_client] failed to create HTTP client");
        if (payload_buf != body) {
            flb_free(payload_buf);
        }

        if (u_conn) {
            flb_upstream_conn_release(u_conn);
        }

        return FLB_RETRY;
    }

    if (c->proxy.host) {
        flb_plg_debug(ctx->ins, "[http_client] proxy host: %s port: %i",
                      c->proxy.host, c->proxy.port);
    }

    /* Allow duplicated headers ? */
    flb_http_allow_duplicated_headers(c, ctx->allow_dup_headers);

    /*
     * Direct assignment of the callback context to the HTTP client context.
     * This needs to be improved through a more clean API.
     */
    c->cb_ctx = ctx->ins->callback;

    flb_http_set_response_timeout(c, ctx->response_timeout);

    if (ctx->read_idle_timeout > 0) {
        flb_http_set_read_idle_timeout(c, ctx->read_idle_timeout);
    }
    else {
        flb_http_set_read_idle_timeout(c, ctx->ins->net_setup.io_timeout);
    }

    /* Append headers */
    if (headers) {
        append_headers(c, headers);
    }
    else if ((ctx->out_format == FLB_PACK_JSON_FORMAT_JSON) ||
        (ctx->out_format == FLB_PACK_JSON_FORMAT_STREAM) ||
        (ctx->out_format == FLB_HTTP_OUT_GELF)) {
        flb_http_add_header(c,
                            FLB_HTTP_CONTENT_TYPE,
                            sizeof(FLB_HTTP_CONTENT_TYPE) - 1,
                            FLB_HTTP_MIME_JSON,
                            sizeof(FLB_HTTP_MIME_JSON) - 1);
    }
    else if (ctx->out_format == FLB_PACK_JSON_FORMAT_LINES) {
        flb_http_add_header(c,
                            FLB_HTTP_CONTENT_TYPE,
                            sizeof(FLB_HTTP_CONTENT_TYPE) - 1,
                            FLB_HTTP_MIME_NDJSON,
                            sizeof(FLB_HTTP_MIME_NDJSON) - 1);
    }
    else if (ctx->out_format == FLB_HTTP_OUT_MSGPACK) {
        flb_http_add_header(c,
                            FLB_HTTP_CONTENT_TYPE,
                            sizeof(FLB_HTTP_CONTENT_TYPE) - 1,
                            FLB_HTTP_MIME_MSGPACK,
                            sizeof(FLB_HTTP_MIME_MSGPACK) - 1);
    }

    if (ctx->header_tag) {
        flb_http_add_header(c,
                            ctx->header_tag,
                            flb_sds_len(ctx->header_tag),
                            tag, tag_len);
    }

    /* Content Encoding: gzip */
    if (compressed == FLB_TRUE) {
        if (ctx->compress_gzip == FLB_TRUE) {
            flb_http_set_content_encoding_gzip(c);
        }
        else if (ctx->compress_snappy == FLB_TRUE) {
            flb_http_set_content_encoding_snappy(c);
        }
        else if (ctx->compress_zstd == FLB_TRUE) {
            flb_http_set_content_encoding_zstd(c);
        }
    }

    /* Basic Auth headers */
    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    flb_config_map_foreach(head, mv, ctx->headers) {
        key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_http_add_header(c,
                            key->str, flb_sds_len(key->str),
                            val->str, flb_sds_len(val->str));
    }

#ifdef FLB_HAVE_SIGNV4
#ifdef FLB_HAVE_AWS
    /* AWS SigV4 headers */
    if (ctx->has_aws_auth == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "signing request with AWS Sigv4");
        signature = flb_signv4_do(c,
                                  FLB_TRUE,  /* normalize URI ? */
                                  FLB_TRUE,  /* add x-amz-date header ? */
                                  time(NULL),
                                  (char *) ctx->aws_region,
                                  (char *) ctx->aws_service,
                                  0, NULL,
                                  ctx->aws_provider);

        if (!signature) {
            flb_plg_error(ctx->ins, "could not sign request with sigv4");
            out_ret = FLB_RETRY;
            goto cleanup;
        }
        flb_sds_destroy(signature);
    }
#endif
#endif

    ret = flb_http_do(c, &b_sent);
    if (ret == 0) {
        /*
         * Only allow the following HTTP status:
         *
         * - 200: OK
         * - 201: Created
         * - 202: Accepted
         * - 203: no authorative resp
         * - 204: No Content
         * - 205: Reset content
         *
         */
        if (c->resp.status < 200 || c->resp.status > 205) {
            if (ctx->log_response_payload &&
                c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                              ctx->host, ctx->port,
                              c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->host, ctx->port, c->resp.status);
            }
            if (c->resp.status >= 400 && c->resp.status < 500 &&
                c->resp.status != 429 && c->resp.status != 408) {
                flb_plg_warn(ctx->ins, "could not flush records to %s:%i (http_do=%i), "
                                "chunk will not be retried",
                                ctx->host, ctx->port, ret);
                out_ret = FLB_ERROR;
            }
            else {
                out_ret = FLB_RETRY;
            }
        }
        else {
            if (ctx->log_response_payload &&
                c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                             ctx->host, ctx->port,
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                             ctx->host, ctx->port,
                             c->resp.status);
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->host, ctx->port, ret);
        out_ret = FLB_RETRY;
    }

cleanup:
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

static int compose_payload_gelf(struct flb_out_http *ctx,
                                const char *data, uint64_t bytes,
                                void **out_body, size_t *out_size)
{
    flb_sds_t s;
    flb_sds_t tmp = NULL;
    size_t size = 0;
    msgpack_object map;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    size = bytes * 1.5;

    /* Allocate buffer for our new payload */
    s = flb_sds_create_size(size);
    if (!s) {
        flb_plg_error(ctx->ins, "flb_sds_create_size failed");
        return FLB_RETRY;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        flb_sds_destroy(s);

        return FLB_RETRY;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map = *log_event.body;

        tmp = flb_msgpack_to_gelf(&s, &map,
                                  &log_event.timestamp,
                                  &(ctx->gelf_fields));
        if (!tmp) {
            flb_plg_error(ctx->ins, "error encoding to GELF");

            flb_sds_destroy(s);
            flb_log_event_decoder_destroy(&log_decoder);

            return FLB_ERROR;
        }

        /* Append new line */
        tmp = flb_sds_cat(s, "\n", 1);
        if (!tmp) {
            flb_plg_error(ctx->ins, "error concatenating records");

            flb_sds_destroy(s);
            flb_log_event_decoder_destroy(&log_decoder);

            return FLB_RETRY;
        }

        s = tmp;
    }

    *out_body = s;
    *out_size = flb_sds_len(s);

    flb_log_event_decoder_destroy(&log_decoder);

    return FLB_OK;
}

static int compose_payload(struct flb_out_http *ctx,
                           const void *in_body, size_t in_size,
                           void **out_body, size_t *out_size,
                           struct flb_config *config)
{
    flb_sds_t encoded;

    *out_body = NULL;
    *out_size = 0;

    if ((ctx->out_format == FLB_PACK_JSON_FORMAT_JSON) ||
        (ctx->out_format == FLB_PACK_JSON_FORMAT_STREAM) ||
        (ctx->out_format == FLB_PACK_JSON_FORMAT_LINES)) {

        encoded = flb_pack_msgpack_to_json_format(in_body,
                                                  in_size,
                                                  ctx->out_format,
                                                  ctx->json_date_format,
                                                  ctx->date_key,
                                                  config->json_escape_unicode);
        if (encoded == NULL) {
            flb_plg_error(ctx->ins, "failed to convert json");
            return FLB_ERROR;
        }
        *out_body = (void*)encoded;
        *out_size = flb_sds_len(encoded);
    }
    else if (ctx->out_format == FLB_HTTP_OUT_GELF) {
        return compose_payload_gelf(ctx, in_body, in_size, out_body, out_size);
    }
    else {
        /* Nothing to do, if the format is msgpack */
        *out_body = (void *)in_body;
        *out_size = in_size;
    }

    return FLB_OK;
}

static char **extract_headers(msgpack_object *obj) {
    size_t i;
    char **headers = NULL;
    size_t str_count;
    msgpack_object_map map;
    msgpack_object_str k;
    msgpack_object_str v;

    if (obj->type != MSGPACK_OBJECT_MAP) {
        goto err;
    }

    map = obj->via.map;
    str_count = map.size * 2 + 1;
    headers = flb_calloc(str_count, sizeof *headers);

    if (!headers) {
        goto err;
    }

    for (i = 0; i < map.size; i++) {
        if (map.ptr[i].key.type != MSGPACK_OBJECT_STR ||
            map.ptr[i].val.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        k = map.ptr[i].key.via.str;
        v = map.ptr[i].val.via.str;

        headers[i * 2] = strndup(k.ptr, k.size);

        if (!headers[i]) {
            goto err;
        }

        headers[i * 2 + 1] = strndup(v.ptr, v.size);

        if (!headers[i]) {
            goto err;
        }
    }

    return headers;

err:
    if (headers) {
        for (i = 0; i < str_count; i++) {
            if (headers[i]) {
                flb_free(headers[i]);
            }
        }
        flb_free(headers);
    }
    return NULL;
}

static int send_all_requests(struct flb_out_http *ctx,
                             const char *data, size_t size,
                             flb_sds_t body_key,
                             flb_sds_t headers_key,
                             struct flb_event_chunk *event_chunk)
{
    msgpack_object map;
    msgpack_object *k;
    msgpack_object *v;
    msgpack_object *start_key;
    const char *body;
    size_t body_size;
    bool body_found;
    bool headers_found;
    char **headers;
    size_t record_count = 0;
    int ret = 0;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    while ((flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        headers = NULL;
        body_found = false;
        headers_found = false;

        map = *log_event.body;

        if (map.type != MSGPACK_OBJECT_MAP) {
            ret = -1;
            break;
        }

        if (!flb_ra_get_kv_pair(ctx->body_ra, map, &start_key, &k, &v)) {
            if (v->type == MSGPACK_OBJECT_STR || v->type == MSGPACK_OBJECT_BIN) {
                body = v->via.str.ptr;
                body_size = v->via.str.size;
                body_found = true;
            }
            else {
                flb_plg_warn(ctx->ins,
                             "failed to extract body using pattern \"%s\" "
                             "(must be a msgpack string or bin)", ctx->body_key);
            }
        }

        if (!flb_ra_get_kv_pair(ctx->headers_ra, map, &start_key, &k, &v)) {
            headers = extract_headers(v);
            if (headers) {
                headers_found = true;
            }
            else {
                flb_plg_warn(ctx->ins,
                             "error extracting headers using pattern \"%s\"",
                             ctx->headers_key);
            }
        }

        if (body_found && headers_found) {
            flb_plg_trace(ctx->ins, "sending record %zu via %s",
                          record_count++,
                          ctx->http_method == FLB_HTTP_POST ? "POST" : "PUT");
            ret = http_request(ctx, body, body_size, event_chunk->tag,
                    flb_sds_len(event_chunk->tag), headers);
        }
        else {
            flb_plg_warn(ctx->ins,
                         "failed to extract body/headers using patterns "
                         "\"%s\" and \"%s\"", ctx->body_key, ctx->headers_key);
            ret = -1;
            continue;
        }

        flb_free(headers);
    }

    flb_log_event_decoder_destroy(&log_decoder);

    return ret;
}

static void cb_http_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret = FLB_ERROR;
    struct flb_out_http *ctx = out_context;
    void *out_body;
    size_t out_size;
    (void) i_ins;

    if (ctx->body_key) {
        ret = send_all_requests(ctx, event_chunk->data, event_chunk->size,
                                ctx->body_key, ctx->headers_key, event_chunk);
        if (ret < 0) {
            flb_plg_error(ctx->ins,
                          "failed to send requests using body key \"%s\"", ctx->body_key);
        }
    }
    else {
        ret = compose_payload(ctx, event_chunk->data, event_chunk->size,
                              &out_body, &out_size, config);
        if (ret != FLB_OK) {
            FLB_OUTPUT_RETURN(ret);
        }

        if ((ctx->out_format == FLB_PACK_JSON_FORMAT_JSON) ||
            (ctx->out_format == FLB_PACK_JSON_FORMAT_STREAM) ||
            (ctx->out_format == FLB_PACK_JSON_FORMAT_LINES) ||
            (ctx->out_format == FLB_HTTP_OUT_GELF)) {
            ret = http_request(ctx, out_body, out_size,
                               event_chunk->tag, flb_sds_len(event_chunk->tag), NULL);
            flb_sds_destroy(out_body);
        }
        else {
            /* msgpack */
            ret = http_request(ctx,
                               event_chunk->data, event_chunk->size,
                               event_chunk->tag, flb_sds_len(event_chunk->tag), NULL);
        }
    }

    FLB_OUTPUT_RETURN(ret);
}

static int cb_http_exit(void *data, struct flb_config *config)
{
    struct flb_out_http *ctx = data;

    flb_http_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "proxy", NULL,
     0, FLB_FALSE, 0,
     "Specify an HTTP Proxy. The expected format of this value is http://host:port. "
    },
    {
     FLB_CONFIG_MAP_BOOL, "allow_duplicated_headers", "true",
     0, FLB_TRUE, offsetof(struct flb_out_http, allow_dup_headers),
     "Specify if duplicated headers are allowed or not"
    },
    {
     FLB_CONFIG_MAP_BOOL, "log_response_payload", "true",
     0, FLB_TRUE, offsetof(struct flb_out_http, log_response_payload),
     "Specify if the response paylod should be logged or not"
    },
    {
     FLB_CONFIG_MAP_TIME, "http.response_timeout", "60s",
     0, FLB_TRUE, offsetof(struct flb_out_http, response_timeout),
     "Set maximum time to wait for a server response"
    },
    {
     FLB_CONFIG_MAP_TIME, "http.read_idle_timeout", "0s",
     0, FLB_TRUE, offsetof(struct flb_out_http, read_idle_timeout),
     "Set maximum allowed time between two consecutive reads"
    },
    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, http_user),
     "Set HTTP auth user"
    },
    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct flb_out_http, http_passwd),
     "Set HTTP auth password"
    },
#ifdef FLB_HAVE_SIGNV4
#ifdef FLB_HAVE_AWS
    {
     FLB_CONFIG_MAP_BOOL, "aws_auth", "false",
     0, FLB_TRUE, offsetof(struct flb_out_http, has_aws_auth),
     "Enable AWS SigV4 authentication"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_service", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, aws_service),
     "AWS destination service code, used by SigV4 authentication"
    },
    FLB_AWS_CREDENTIAL_BASE_CONFIG_MAP(FLB_HTTP_AWS_CREDENTIAL_PREFIX),
#endif
#endif
    {
     FLB_CONFIG_MAP_STR, "header_tag", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, header_tag),
     "Set a HTTP header which value is the Tag"
    },
    {
     FLB_CONFIG_MAP_STR, "format", "json",
     0, FLB_TRUE, offsetof(struct flb_out_http, format),
     "Set desired payload format: json, json_stream, json_lines, gelf or msgpack"
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
     FBL_PACK_JSON_DATE_FORMAT_DESCRIPTION
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_out_http, json_date_key),
     "Specify the name of the date field in output"
    },
    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     "Set payload compression mechanism. Option available are 'gzip', 'snappy' and 'zstd'"
    },
    {
     FLB_CONFIG_MAP_SLIST_1, "header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_out_http, headers),
     "Add a HTTP header key/value pair. Multiple headers can be set"
    },
    {
     FLB_CONFIG_MAP_STR, "uri", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, uri),
     "Specify an optional HTTP URI for the target web server, e.g: /something"
    },
    {
     FLB_CONFIG_MAP_STR, "http_method", "POST",
     0, FLB_FALSE, 0,
     "Specify the HTTP method to use. Supported methods are POST and PUT"
    },

    /* Gelf Properties */
    {
     FLB_CONFIG_MAP_STR, "gelf_timestamp_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, gelf_fields.timestamp_key),
     "Specify the key to use for 'timestamp' in gelf format"
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_host_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, gelf_fields.host_key),
     "Specify the key to use for the 'host' in gelf format"
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_short_message_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, gelf_fields.short_message_key),
     "Specify the key to use as the 'short' message in gelf format"
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_full_message_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, gelf_fields.full_message_key),
     "Specify the key to use for the 'full' message in gelf format"
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_level_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, gelf_fields.level_key),
     "Specify the key to use for the 'level' in gelf format"
    },
    {
     FLB_CONFIG_MAP_STR, "body_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, body_key),
     "Specify the key which contains the body"
    },
    {
     FLB_CONFIG_MAP_STR, "headers_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, headers_key),
     "Specify the key which contains the headers"
    },

    /* EOF */
    {0}
};

static int cb_http_format_test(struct flb_config *config,
                               struct flb_input_instance *ins,
                               void *plugin_context,
                               void *flush_ctx,
                               int event_type,
                               const char *tag, int tag_len,
                               const void *data, size_t bytes,
                               void **out_data, size_t *out_size)
{
    struct flb_out_http *ctx = plugin_context;
    int ret;

    ret = compose_payload(ctx, data, bytes, out_data, out_size, config);
    if (ret != FLB_OK) {
        flb_error("ret=%d", ret);
        return -1;
    }
    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_http_plugin = {
    .name        = "http",
    .description = "HTTP Output",
    .cb_init     = cb_http_init,
    .cb_pre_run  = NULL,
    .cb_flush    = cb_http_flush,
    .cb_exit     = cb_http_exit,
    .config_map  = config_map,

    /* for testing */
    .test_formatter.callback = cb_http_format_test,

    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .workers     = 2
};
