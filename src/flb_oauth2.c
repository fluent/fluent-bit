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
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_jsmn.h>

#include <time.h>
#include <string.h>
#include <stddef.h>

/* Config map for OAuth2 configuration */
struct flb_config_map oauth2_config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "oauth2.enable", "false",
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, enabled),
     "Enable OAuth2 client credentials for outgoing requests"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.token_url", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, token_url),
     "OAuth2 token endpoint URL"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.client_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, client_id),
     "OAuth2 client_id"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.client_secret", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, client_secret),
     "OAuth2 client_secret"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.scope", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, scope),
     "Optional OAuth2 scope"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.audience", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, audience),
     "Optional OAuth2 audience parameter"
    },
    {
     FLB_CONFIG_MAP_INT, "oauth2.refresh_skew_seconds", "60",
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, refresh_skew),
     "Seconds before expiry to refresh the access token"
    },
    {
     FLB_CONFIG_MAP_TIME, "oauth2.timeout", "0s",
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, timeout),
     "Timeout for OAuth2 token requests (defaults to response_timeout when unset)"
    },
    {
     FLB_CONFIG_MAP_TIME, "oauth2.connect_timeout", "0s",
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, connect_timeout),
     "Connect timeout for OAuth2 token requests"
    },

    /* EOF */
    {0}
};

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

static inline int key_cmp(const char *str, int len, const char *cmp)
{
    if (strlen(cmp) != len) {
        return -1;
    }

    return strncasecmp(str, cmp, len);
}

static void oauth2_reset_state(struct flb_oauth2 *ctx)
{
    ctx->expires_in = 0;
    ctx->expires_at = 0;

    if (ctx->access_token) {
        flb_sds_destroy(ctx->access_token);
        ctx->access_token = NULL;
    }

    if (ctx->token_type) {
        flb_sds_destroy(ctx->token_type);
        ctx->token_type = NULL;
    }
}

static void oauth2_apply_defaults(struct flb_oauth2_config *cfg)
{
    cfg->enabled = FLB_TRUE;
    cfg->auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg->refresh_skew = FLB_OAUTH2_DEFAULT_SKEW_SECS;
    cfg->timeout = 0;
    cfg->connect_timeout = 0;
    /* Initialize all pointer fields to NULL to avoid using uninitialized values */
    cfg->token_url = NULL;
    cfg->client_id = NULL;
    cfg->client_secret = NULL;
    cfg->scope = NULL;
    cfg->audience = NULL;
}

static int oauth2_clone_config(struct flb_oauth2_config *dst,
                               const struct flb_oauth2_config *src)
{
    oauth2_apply_defaults(dst);

    if (!src) {
        return 0;
    }

    dst->enabled = src->enabled;
    dst->auth_method = src->auth_method;

    if (src->refresh_skew > 0) {
        dst->refresh_skew = src->refresh_skew;
    }

    dst->timeout = src->timeout;
    dst->connect_timeout = src->connect_timeout;

    if (src->token_url) {
        dst->token_url = flb_sds_create(src->token_url);
        if (!dst->token_url) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->client_id) {
        dst->client_id = flb_sds_create(src->client_id);
        if (!dst->client_id) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->client_secret) {
        dst->client_secret = flb_sds_create(src->client_secret);
        if (!dst->client_secret) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->scope) {
        dst->scope = flb_sds_create(src->scope);
        if (!dst->scope) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->audience) {
        dst->audience = flb_sds_create(src->audience);
        if (!dst->audience) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    return 0;
}

void flb_oauth2_config_destroy(struct flb_oauth2_config *cfg)
{
    if (!cfg) {
        return;
    }

    flb_sds_destroy(cfg->token_url);
    cfg->token_url = NULL;
    flb_sds_destroy(cfg->client_id);
    cfg->client_id = NULL;
    flb_sds_destroy(cfg->client_secret);
    cfg->client_secret = NULL;
    flb_sds_destroy(cfg->scope);
    cfg->scope = NULL;
    flb_sds_destroy(cfg->audience);
    cfg->audience = NULL;
}

static int oauth2_setup_upstream(struct flb_oauth2 *ctx,
                                 struct flb_config *config,
                                 const char *auth_url)
{
    int ret;
    char *prot = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;

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

    ctx->tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                              FLB_TRUE,
                              -1,
                              NULL,
                              NULL,
                              NULL,
                              NULL,
                              NULL,
                              NULL);
    if (!ctx->tls) {
        flb_error("[oauth2] error initializing TLS context");
        goto error;
    }

    if (strcmp(prot, "https") == 0) {
        ctx->u = flb_upstream_create_url(config, auth_url, FLB_IO_TLS, ctx->tls);
    }
    else {
        ctx->u = flb_upstream_create_url(config, auth_url, FLB_IO_TCP, NULL);
    }

    if (!ctx->u) {
        flb_error("[oauth2] error creating upstream context");
        goto error;
    }

    flb_stream_disable_async_mode(&ctx->u->base);

    if (ctx->cfg.connect_timeout > 0) {
        ctx->u->base.net.connect_timeout = ctx->cfg.connect_timeout;
    }

    free_temporary_buffers();

    return 0;

error:
    free_temporary_buffers();

    return -1;
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
    uint64_t expires_in = 0;
    flb_sds_t access_token = NULL;
    flb_sds_t token_type = NULL;

    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tokens_size);
    if (!tokens) {
        flb_errno();
        return -1;
    }

    ret = jsmn_parse(&parser, json_data, json_size, tokens, tokens_size);
    if (ret <= 0) {
        flb_error("[oauth2] cannot parse payload");
        flb_free(tokens);
        return -1;
    }

    t = &tokens[0];
    if (t->type != JSMN_OBJECT) {
        flb_error("[oauth2] invalid JSON response");
        flb_free(tokens);
        return -1;
    }

    for (i = 1; i < ret; i++) {
        t = &tokens[i];

        if (t->type != JSMN_STRING) {
            continue;
        }

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }

        key = json_data + t->start;
        key_len = (t->end - t->start);

        i++;
        t = &tokens[i];
        val = json_data + t->start;
        val_len = (t->end - t->start);

        if (key_cmp(key, key_len, "access_token") == 0) {
            access_token = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "token_type") == 0) {
            token_type = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "expires_in") == 0) {
            expires_in = strtoull(val, NULL, 10);
        }
    }

    flb_free(tokens);

    if (!access_token) {
        oauth2_reset_state(ctx);
        return -1;
    }

    if (!token_type) {
        token_type = flb_sds_create("Bearer");
        flb_debug("[oauth2] token_type missing; defaulting to Bearer");
    }

    if (expires_in == 0) {
        expires_in = FLB_OAUTH2_DEFAULT_EXPIRES;
        flb_warn("[oauth2] expires_in missing; defaulting to %d seconds",
                 FLB_OAUTH2_DEFAULT_EXPIRES);
    }

    oauth2_reset_state(ctx);

    ctx->access_token = access_token;
    ctx->token_type = token_type;
    ctx->expires_in = expires_in;
    ctx->expires_at = time(NULL) + expires_in;

    return 0;
}

static flb_sds_t oauth2_append_kv(flb_sds_t buffer, const char *key,
                                  const char *value)
{
    flb_sds_t tmp;

    if (!value) {
        return buffer;
    }

    tmp = flb_uri_encode(value, strlen(value));
    if (!tmp) {
        flb_errno();
        return NULL;
    }

    if (flb_sds_len(buffer) > 0) {
        buffer = flb_sds_cat(buffer, "&", 1);
        if (!buffer) {
            flb_sds_destroy(tmp);
            return NULL;
        }
    }

    buffer = flb_sds_cat(buffer, key, strlen(key));
    if (!buffer) {
        flb_sds_destroy(tmp);
        return NULL;
    }

    buffer = flb_sds_cat(buffer, "=", 1);
    if (!buffer) {
        flb_sds_destroy(tmp);
        return NULL;
    }

    buffer = flb_sds_cat(buffer, tmp, flb_sds_len(tmp));
    flb_sds_destroy(tmp);

    return buffer;
}

static flb_sds_t oauth2_build_body(struct flb_oauth2 *ctx)
{
    flb_sds_t body;

    if (ctx->payload_manual == FLB_TRUE && ctx->payload) {
        return flb_sds_create_len(ctx->payload, flb_sds_len(ctx->payload));
    }

    body = flb_sds_create_size(128);
    if (!body) {
        return NULL;
    }

    body = oauth2_append_kv(body, "grant_type", "client_credentials");
    if (!body) {
        return NULL;
    }

    if (ctx->cfg.scope) {
        body = oauth2_append_kv(body, "scope", ctx->cfg.scope);
        if (!body) {
            return NULL;
        }
    }

    if (ctx->cfg.audience) {
        body = oauth2_append_kv(body, "audience", ctx->cfg.audience);
        if (!body) {
            return NULL;
        }
    }

    if (ctx->cfg.auth_method == FLB_OAUTH2_AUTH_METHOD_POST) {
        if (ctx->cfg.client_id) {
            body = oauth2_append_kv(body, "client_id", ctx->cfg.client_id);
            if (!body) {
                return NULL;
            }
        }

        if (ctx->cfg.client_secret) {
            body = oauth2_append_kv(body, "client_secret", ctx->cfg.client_secret);
            if (!body) {
                return NULL;
            }
        }
    }

    return body;
}

static int oauth2_http_request(struct flb_oauth2 *ctx, flb_sds_t body)
{
    int ret;
    size_t b_sent = 0;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_stream_enable_flags(&ctx->u->base, FLB_IO_IPV6);
        u_conn = flb_upstream_conn_get(ctx->u);
        if (!u_conn) {
            flb_error("[oauth2] could not get an upstream connection to %s:%i",
                      ctx->u->tcp_host, ctx->u->tcp_port);
            flb_stream_disable_flags(&ctx->u->base, FLB_IO_IPV6);
            return -1;
        }
    }

    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        body, flb_sds_len(body),
                        ctx->host, atoi(ctx->port),
                        NULL, 0);
    if (!c) {
        flb_error("[oauth2] error creating HTTP client context");
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    if (ctx->cfg.timeout > 0) {
        flb_http_set_response_timeout(c, ctx->cfg.timeout);
        flb_http_set_read_idle_timeout(c, ctx->cfg.timeout);
    }

    flb_http_add_header(c,
                        FLB_HTTP_HEADER_CONTENT_TYPE,
                        sizeof(FLB_HTTP_HEADER_CONTENT_TYPE) - 1,
                        FLB_OAUTH2_HTTP_ENCODING,
                        sizeof(FLB_OAUTH2_HTTP_ENCODING) - 1);

    if (ctx->cfg.auth_method == FLB_OAUTH2_AUTH_METHOD_BASIC &&
        ctx->cfg.client_id && ctx->cfg.client_secret) {
        ret = flb_http_basic_auth(c, ctx->cfg.client_id, ctx->cfg.client_secret);
        if (ret != 0) {
            flb_error("[oauth2] could not compose basic authorization header");
            flb_http_client_destroy(c);
            flb_upstream_conn_release(u_conn);
            return -1;
        }
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[oauth2] cannot issue request, http_do=%i", ret);
    }
    else {
        flb_debug("[oauth2] HTTP Status=%i", c->resp.status);
    }

    if (c->resp.payload_size > 0 && c->resp.status == 200) {
        ret = flb_oauth2_parse_json_response(c->resp.payload,
                                             c->resp.payload_size, ctx);
        if (ret == 0) {
            flb_info("[oauth2] access token from '%s:%s' retrieved", ctx->host, ctx->port);
            flb_http_client_destroy(c);
            flb_upstream_conn_release(u_conn);
            return 0;
        }
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return -1;
}

static int oauth2_refresh_locked(struct flb_oauth2 *ctx)
{
    int ret;
    flb_sds_t body;

    body = oauth2_build_body(ctx);
    if (!body) {
        flb_error("[oauth2] could not build request body");
        return -1;
    }

    ret = oauth2_http_request(ctx, body);
    flb_sds_destroy(body);

    return ret;
}

static int oauth2_token_needs_refresh(struct flb_oauth2 *ctx, int force_refresh)
{
    time_t now;

    if (force_refresh) {
        return FLB_TRUE;
    }

    if (!ctx->access_token) {
        return FLB_TRUE;
    }

    now = time(NULL);

    if (ctx->expires_at == 0) {
        return FLB_TRUE;
    }

    if (now >= (ctx->expires_at - ctx->refresh_skew)) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

struct flb_oauth2 *flb_oauth2_create(struct flb_config *config,
                                     const char *auth_url, int expire_sec)
{
    struct flb_oauth2_config cfg;
    struct flb_oauth2 *ctx;

    (void) expire_sec;

    oauth2_apply_defaults(&cfg);
    cfg.token_url = flb_sds_create(auth_url);
    cfg.refresh_skew = FLB_OAUTH2_DEFAULT_SKEW_SECS;

    ctx = flb_oauth2_create_from_config(config, &cfg);

    flb_oauth2_config_destroy(&cfg);

    return ctx;
}

struct flb_oauth2 *flb_oauth2_create_from_config(struct flb_config *config,
                                const struct flb_oauth2_config *cfg)
{
    int ret;
    struct flb_oauth2 *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_oauth2));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    oauth2_apply_defaults(&ctx->cfg);

    ret = oauth2_clone_config(&ctx->cfg, cfg);
    if (ret != 0) {
        flb_free(ctx);
        return NULL;
    }

    if (!ctx->cfg.token_url) {
        flb_error("[oauth2] token_url is not set");
        flb_oauth2_destroy(ctx);
        return NULL;
    }

    ctx->auth_url = flb_sds_create(ctx->cfg.token_url);
    if (!ctx->auth_url) {
        flb_errno();
        flb_oauth2_destroy(ctx);
        return NULL;
    }

    ctx->payload = flb_sds_create_size(1024);
    if (!ctx->payload) {
        flb_errno();
        flb_oauth2_destroy(ctx);
        return NULL;
    }

    ctx->refresh_skew = ctx->cfg.refresh_skew;
    if (ctx->refresh_skew <= 0) {
        ctx->refresh_skew = FLB_OAUTH2_DEFAULT_SKEW_SECS;
    }

    ret = flb_lock_init(&ctx->lock);
    if (ret != 0) {
        flb_oauth2_destroy(ctx);
        return NULL;
    }

    ret = oauth2_setup_upstream(ctx, config, ctx->auth_url);
    if (ret != 0) {
        flb_oauth2_destroy(ctx);
        return NULL;
    }

    return ctx;
}

void flb_oauth2_destroy(struct flb_oauth2 *ctx)
{
    if (!ctx) {
        return;
    }

    oauth2_reset_state(ctx);

    flb_sds_destroy(ctx->auth_url);
    flb_sds_destroy(ctx->payload);
    flb_sds_destroy(ctx->host);
    flb_sds_destroy(ctx->port);
    flb_sds_destroy(ctx->uri);

    if (ctx->tls) {
        flb_tls_destroy(ctx->tls);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_oauth2_config_destroy(&ctx->cfg);
    flb_lock_destroy(&ctx->lock);

    flb_free(ctx);
}

void flb_oauth2_payload_clear(struct flb_oauth2 *ctx)
{
    if (!ctx || !ctx->payload) {
        return;
    }

    flb_sds_len_set(ctx->payload, 0);
    ctx->payload[0] = '\0';
    ctx->payload_manual = FLB_TRUE;
    oauth2_reset_state(ctx);
}

int flb_oauth2_payload_append(struct flb_oauth2 *ctx,
                              const char *key_str, int key_len,
                              const char *val_str, int val_len)
{
    int ret;
    int size;
    flb_sds_t tmp;

    if (key_len == -1) {
        key_len = strlen(key_str);
    }
    if (val_len == -1) {
        val_len = strlen(val_str);
    }

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
        ret = flb_sds_cat_safe(&ctx->payload, "&", 1);
        if (ret != 0) {
            return -1;
        }
    }

    ret = flb_sds_cat_safe(&ctx->payload, key_str, key_len);
    if (ret != 0) {
        return -1;
    }

    ret = flb_sds_cat_safe(&ctx->payload, "=", 1);
    if (ret != 0) {
        return -1;
    }

    ret = flb_sds_cat_safe(&ctx->payload, val_str, val_len);
    if (ret != 0) {
        return -1;
    }

    ctx->payload_manual = FLB_TRUE;
    return 0;
}

static int oauth2_get_token_locked(struct flb_oauth2 *ctx,
                                   flb_sds_t *token_out,
                                   int force_refresh)
{
    int ret = 0;

    if (oauth2_token_needs_refresh(ctx, force_refresh) == FLB_TRUE) {
        ret = oauth2_refresh_locked(ctx);
        if (ret != 0) {
            return ret;
        }
    }

    *token_out = ctx->access_token;

    return (*token_out != NULL) ? 0 : -1;
}

int flb_oauth2_get_access_token(struct flb_oauth2 *ctx,
                                flb_sds_t *token_out,
                                int force_refresh)
{
    int ret;

    if (ctx->cfg.enabled == FLB_FALSE) {
        return -1;
    }

    ret = flb_lock_acquire(&ctx->lock,
                           FLB_LOCK_DEFAULT_RETRY_LIMIT,
                           FLB_LOCK_DEFAULT_RETRY_DELAY);
    if (ret != 0) {
        return -1;
    }

    ret = oauth2_get_token_locked(ctx, token_out, force_refresh);

    flb_lock_release(&ctx->lock,
                     FLB_LOCK_DEFAULT_RETRY_LIMIT,
                     FLB_LOCK_DEFAULT_RETRY_DELAY);

    return ret;
}

char *flb_oauth2_token_get(struct flb_oauth2 *ctx)
{
    flb_sds_t token = NULL;
    int ret;

    ret = flb_oauth2_get_access_token(ctx, &token, FLB_FALSE);
    if (ret != 0) {
        return NULL;
    }

    return token;
}

char *flb_oauth2_token_get_ng(struct flb_oauth2 *ctx)
{
    return flb_oauth2_token_get(ctx);
}

void flb_oauth2_invalidate_token(struct flb_oauth2 *ctx)
{
    int ret;

    ret = flb_lock_acquire(&ctx->lock,
                           FLB_LOCK_DEFAULT_RETRY_LIMIT,
                           FLB_LOCK_DEFAULT_RETRY_DELAY);
    if (ret != 0) {
        return;
    }

    ctx->expires_at = 0;

    flb_lock_release(&ctx->lock,
                     FLB_LOCK_DEFAULT_RETRY_LIMIT,
                     FLB_LOCK_DEFAULT_RETRY_DELAY);
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
    if (ctx->expires_at <= now) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

struct mk_list *flb_oauth2_get_config_map(struct flb_config *config)
{
    struct mk_list *config_map;

    config_map = flb_config_map_create(config, oauth2_config_map);

    return config_map;
}

