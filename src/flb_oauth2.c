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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_jsmn.h>

#define free_temporary_buffers()                 \
    if (prot) {                                 \
        flb_free(prot);                         \
    }                                           \
    if (host) {                                 \
        flb_free(host);                         \
    }                                           \
    if (port) {                                 \
        flb_free(port);                         \
    }                                           \
    if (uri) {                                  \
        flb_free(uri);                          \
    }

static inline int key_cmp(const char *str, int len, const char *cmp) {

    if (strlen(cmp) != len) {
        return -1;
    }

    return strncasecmp(str, cmp, len);
}

int flb_oauth2_parse_json_response(const char *json_data, size_t json_size,
                                   struct flb_oauth2 *ctx)
{
    int i;
    int ret;
    int key_len;
    int val_len;
    int tokens_size = 32;
    const char *key;
    const char *val;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;

    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tokens_size);
    if (!tokens) {
        flb_errno();
        return -1;
    }

    ret = jsmn_parse(&parser, json_data, json_size, tokens, tokens_size);
    if (ret <= 0) {
        flb_error("[oauth2] cannot parse payload:\n%s", json_data);
        flb_free(tokens);
        return -1;
    }

    t = &tokens[0];
    if (t->type != JSMN_OBJECT) {
        flb_error("[oauth2] invalid JSON response:\n%s", json_data);
        flb_free(tokens);
        return -1;
    }

    /* Parse JSON tokens */
    for (i = 1; i < ret; i++) {
        t = &tokens[i];

        if (t->type != JSMN_STRING) {
            continue;
        }

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)){
            break;
        }

        /* Key */
        key = json_data + t->start;
        key_len = (t->end - t->start);

        /* Value */
        i++;
        t = &tokens[i];
        val = json_data + t->start;
        val_len = (t->end - t->start);

        if (key_cmp(key, key_len, "access_token") == 0) {
            ctx->access_token = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "token_type") == 0) {
            ctx->token_type = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "expires_in") == 0) {
            ctx->expires_in = atol(val);

            /*
             * Our internal expiration time must be lower that the one set
             * by the remote end-point, so we can use valid cached values
             * if a token renewal is in place. So we decrease the expire
             * interval -10%.
             */
            ctx->expires_in -= (ctx->expires_in * 0.10);
        }
    }

    flb_free(tokens);
    if (!ctx->access_token || !ctx->token_type || ctx->expires_in < 60) {
        flb_sds_destroy(ctx->access_token);
        flb_sds_destroy(ctx->token_type);
        ctx->expires_in = 0;
        return -1;
    }

    return 0;
}

struct flb_oauth2 *flb_oauth2_create(struct flb_config *config,
                                     const char *auth_url, int expire_sec)
{
    int ret;
    char *prot = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    struct flb_oauth2 *ctx;

    /* allocate context */
    ctx = flb_calloc(1, sizeof(struct flb_oauth2));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* register token url */
    ctx->auth_url = flb_sds_create(auth_url);
    if (!ctx->auth_url) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    /* default payload size to 1kb */
    ctx->payload = flb_sds_create_size(1024);
    if (!ctx->payload) {
        flb_errno();
        flb_oauth2_destroy(ctx);
        return NULL;
    }

    ctx->issued = time(NULL);
    ctx->expires = ctx->issued + expire_sec;

    /* Parse and split URL */
    ret = flb_utils_url_split(auth_url, &prot, &host, &port, &uri);
    if (ret == -1) {
        flb_error("[oauth2] invalid URL: %s", auth_url);
        goto error;
    }

    if (!prot || (strcmp(prot, "https") != 0 && strcmp(prot, "http") != 0)) {
        flb_error("[oauth2] invalid endpoint protocol: %s", auth_url);
        goto error;
    }

    if (!host) {
        flb_error("[oauth2] invalid URL host: %s", auth_url);
        goto error;
    }

    /* Populate context */
    ctx->host = flb_sds_create(host);
    if (!ctx->host) {
        flb_errno();
        goto error;
    }
    if (port) {
        ctx->port = flb_sds_create(port);
    }
    else {
        ctx->port = flb_sds_create(FLB_OAUTH2_PORT);
    }
    if (!ctx->port) {
        flb_errno();
        goto error;
    }
    ctx->uri = flb_sds_create(uri);
    if (!ctx->uri) {
        flb_errno();
        goto error;
    }

    /* Create TLS context */
    ctx->tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                              FLB_TRUE,  /* verify */
                              -1,        /* debug */
                              NULL,      /* vhost */
                              NULL,      /* ca_path */
                              NULL,      /* ca_file */
                              NULL,      /* crt_file */
                              NULL,      /* key_file */
                              NULL);     /* key_passwd */
    if (!ctx->tls) {
        flb_error("[oauth2] error initializing TLS context");
        goto error;
    }

    /* Create Upstream context */
    if (strcmp(prot, "https") == 0) {
        ctx->u = flb_upstream_create_url(config, auth_url,
                                        FLB_IO_TLS, ctx->tls);
    }
    else if (strcmp(prot, "http") == 0) {
        ctx->u = flb_upstream_create_url(config, auth_url,
                                        FLB_IO_TCP, NULL);
    }

    if (!ctx->u) {
        flb_error("[oauth2] error creating upstream context");
        goto error;
    }

    /* Remove Upstream Async flag */
    flb_stream_disable_async_mode(&ctx->u->base);

    free_temporary_buffers();
    return ctx;

 error:
    free_temporary_buffers();
    flb_oauth2_destroy(ctx);

    return NULL;
}

/* Clear the current payload and token */
void flb_oauth2_payload_clear(struct flb_oauth2 *ctx)
{
    flb_sds_len_set(ctx->payload, 0);
    ctx->payload[0] = '\0';
    ctx->expires_in = 0;
    if (ctx->access_token){
        flb_sds_destroy(ctx->access_token);
        ctx->access_token = NULL;
    }
    if (ctx->token_type){
        flb_sds_destroy(ctx->token_type);
        ctx->token_type = NULL;
    }
}

/* Append a key/value to the request body */
int flb_oauth2_payload_append(struct flb_oauth2 *ctx,
                              const char *key_str, int key_len,
                              const char *val_str, int val_len)
{
    int size;
    flb_sds_t tmp;

    if (key_len == -1) {
        key_len = strlen(key_str);
    }
    if (val_len == -1) {
        val_len = strlen(val_str);
    }

    /*
     * Make sure we have enough space in the sds buffer, otherwise
     * add more capacity (so further flb_sds_cat calls do not
     * realloc().
     */
    size = key_len + val_len + 2;
    if (flb_sds_avail(ctx->payload) < size) {
        tmp = flb_sds_increase(ctx->payload, size);
        if (!tmp) {
            flb_errno();
            return -1;
        }

        if (tmp != ctx->payload) {
            ctx->payload = tmp;
        }
    }

    if (flb_sds_len(ctx->payload) > 0) {
        flb_sds_cat(ctx->payload, "&", 1);
    }

    /* Append key and value */
    flb_sds_cat(ctx->payload, key_str, key_len);
    flb_sds_cat(ctx->payload, "=", 1);
    flb_sds_cat(ctx->payload, val_str, val_len);

    return 0;
}

void flb_oauth2_destroy(struct flb_oauth2 *ctx)
{
    flb_sds_destroy(ctx->auth_url);
    flb_sds_destroy(ctx->payload);

    flb_sds_destroy(ctx->host);
    flb_sds_destroy(ctx->port);
    flb_sds_destroy(ctx->uri);

    flb_sds_destroy(ctx->access_token);
    flb_sds_destroy(ctx->token_type);

    flb_upstream_destroy(ctx->u);
    flb_tls_destroy(ctx->tls);

    flb_free(ctx);
}

char *flb_oauth2_token_get_ng(struct flb_oauth2 *ctx)
{
    int ret;
    time_t now;
    struct flb_http_client_ng http_client;
    struct flb_http_response *response;
    struct flb_http_request  *request;
    uint64_t http_client_flags;

    now = time(NULL);
    if (ctx->access_token) {
        /* validate unexpired token */
        if (ctx->expires > now && flb_sds_len(ctx->access_token) > 0) {
            return ctx->access_token;
        }
    }

    http_client_flags = FLB_HTTP_CLIENT_FLAG_AUTO_DEFLATE |
                        FLB_HTTP_CLIENT_FLAG_AUTO_INFLATE;

    ret = flb_http_client_ng_init(&http_client,
                                  NULL,
                                  ctx->u,
                                  HTTP_PROTOCOL_VERSION_11,
                                  http_client_flags);

    if (ret != 0) {
        flb_debug("[oauth2] http client creation error");

        return NULL;
    }

    request = flb_http_client_request_builder(
                    &http_client,
                    FLB_HTTP_CLIENT_ARGUMENT_METHOD(FLB_HTTP_POST),
                    FLB_HTTP_CLIENT_ARGUMENT_HOST(ctx->host),
                    FLB_HTTP_CLIENT_ARGUMENT_URI(ctx->uri),
                    FLB_HTTP_CLIENT_ARGUMENT_CONTENT_TYPE(
                        FLB_OAUTH2_HTTP_ENCODING),
                    FLB_HTTP_CLIENT_ARGUMENT_BODY(ctx->payload,
                                                  cfl_sds_len(ctx->payload),
                                                  NULL));

    if (request == NULL) {
        flb_stream_enable_flags(&ctx->u->base, FLB_IO_IPV6);

        request = flb_http_client_request_builder(
                        &http_client,
                        FLB_HTTP_CLIENT_ARGUMENT_METHOD(FLB_HTTP_POST),
                        FLB_HTTP_CLIENT_ARGUMENT_HOST(ctx->host),
                        FLB_HTTP_CLIENT_ARGUMENT_URI(ctx->uri),
                        FLB_HTTP_CLIENT_ARGUMENT_CONTENT_TYPE(
                            FLB_OAUTH2_HTTP_ENCODING),
                        FLB_HTTP_CLIENT_ARGUMENT_BODY(ctx->payload,
                                                    cfl_sds_len(ctx->payload),
                                                    NULL));
        if (request == NULL) {
            flb_error("[oauth2] could not get an upstream connection to %s:%i",
                      ctx->u->tcp_host, ctx->u->tcp_port);

            flb_stream_disable_flags(&ctx->u->base, FLB_IO_IPV6);
            flb_http_client_request_destroy(request, FLB_TRUE);
            flb_http_client_ng_destroy(&http_client);

            return NULL;
        }
    }

    response = flb_http_client_request_execute(request);

    if (response == NULL) {
        flb_debug("[oauth2] http request execution error");

        flb_http_client_request_destroy(request, FLB_TRUE);
        flb_http_client_ng_destroy(&http_client);

        return NULL;
    }

    flb_info("[oauth2] HTTP Status=%i", response->status);
    if (response->body != NULL &&
        cfl_sds_len(response->body) > 0) {
        flb_info("[oauth2] payload:\n%s", response->body);
    }

    /* Extract token */
    if (response->body != NULL &&
        cfl_sds_len(response->body) > 0 &&
        response->status == 200) {
        ret = flb_oauth2_parse_json_response(response->body,
                                             cfl_sds_len(response->body),
                                             ctx);
        if (ret == 0) {
            flb_info("[oauth2] access token from '%s:%s' retrieved",
                     ctx->host, ctx->port);

            flb_http_client_request_destroy(request, FLB_TRUE);
            flb_http_client_ng_destroy(&http_client);

            ctx->issued = time(NULL);
            ctx->expires = ctx->issued + ctx->expires_in;

            return ctx->access_token;
        }
    }

    flb_http_client_request_destroy(request, FLB_TRUE);
    flb_http_client_ng_destroy(&http_client);

    return NULL;
}

char *flb_oauth2_token_get(struct flb_oauth2 *ctx)
{
    int ret;
    size_t b_sent;
    time_t now;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    now = time(NULL);
    if (ctx->access_token) {
        /* validate unexpired token */
        if (ctx->expires > now && flb_sds_len(ctx->access_token) > 0) {
            return ctx->access_token;
        }
    }

    /* Get Token and store it in the context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_stream_enable_flags(&ctx->u->base, FLB_IO_IPV6);
        u_conn = flb_upstream_conn_get(ctx->u);
        if (!u_conn) {
            flb_error("[oauth2] could not get an upstream connection to %s:%i",
                      ctx->u->tcp_host, ctx->u->tcp_port);
            flb_stream_disable_flags(&ctx->u->base, FLB_IO_IPV6);
            return NULL;
        }
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        ctx->payload, flb_sds_len(ctx->payload),
                        ctx->host, atoi(ctx->port),
                        NULL, 0);
    if (!c) {
        flb_error("[oauth2] error creating HTTP client context");
        flb_upstream_conn_release(u_conn);
        return NULL;
    }

    /* Append HTTP Header */
    flb_http_add_header(c,
                        FLB_HTTP_HEADER_CONTENT_TYPE,
                        sizeof(FLB_HTTP_HEADER_CONTENT_TYPE) -1,
                        FLB_OAUTH2_HTTP_ENCODING,
                        sizeof(FLB_OAUTH2_HTTP_ENCODING) - 1);

    /* Issue request */
    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[oauth2] cannot issue request, http_do=%i", ret);
    }
    else {
        flb_info("[oauth2] HTTP Status=%i", c->resp.status);
        if (c->resp.payload_size > 0) {
            if (c->resp.status == 200) {
                flb_debug("[oauth2] payload:\n%s", c->resp.payload);
            }
            else {
                flb_info("[oauth2] payload:\n%s", c->resp.payload);
            }
        }
    }

    /* Extract token */
    if (c->resp.payload_size > 0 && c->resp.status == 200) {
        ret = flb_oauth2_parse_json_response(c->resp.payload,
                                             c->resp.payload_size, ctx);
        if (ret == 0) {
            flb_info("[oauth2] access token from '%s:%s' retrieved",
                     ctx->host, ctx->port);
            flb_http_client_destroy(c);
            flb_upstream_conn_release(u_conn);
            ctx->issued = time(NULL);
            ctx->expires = ctx->issued + ctx->expires_in;
            return ctx->access_token;
        }
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return NULL;
}

int flb_oauth2_token_len(struct flb_oauth2 *ctx)
{
    if (!ctx->access_token) {
        return -1;
    }

    return flb_sds_len(ctx->access_token);
}

int flb_oauth2_token_expired(struct flb_oauth2 *ctx)
{
    time_t now;

    if (!ctx->access_token) {
        return FLB_TRUE;
    }

    now = time(NULL);
    if (ctx->expires <= now) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}
