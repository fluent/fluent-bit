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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto.h>

#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <limits.h>

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define FLB_OAUTH2_DEFAULT_ASSERTION_TTL 300
#define FLB_OAUTH2_DEFAULT_ASSERTION_HEADER "kid"
#define FLB_OAUTH2_ASSERTION_UUID_LEN 37

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
     FLB_CONFIG_MAP_STR, "oauth2.resource", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, resource),
     "Optional OAuth2 resource parameter"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.auth_method", "basic",
     0, FLB_FALSE, 0,
     "OAuth2 client authentication method: basic, post or private_key_jwt"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.jwt_key_file", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config,
                           jwt_key_file),
     "Path to PEM private key for private_key_jwt authentication"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.jwt_cert_file", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config,
                           jwt_cert_file),
     "Path to certificate file for private_key_jwt kid/x5t derivation"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.jwt_aud", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, jwt_aud),
     "Audience used in private_key_jwt assertion (defaults to token_url)"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.jwt_header", "kid",
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, jwt_header),
     "JWT header claim name for thumbprint in private_key_jwt (e.g., kid, x5t)"
    },
    {
     FLB_CONFIG_MAP_INT, "oauth2.jwt_ttl_seconds", "300",
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, jwt_ttl),
     "Lifetime in seconds for private_key_jwt client assertions"
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
    {
     FLB_CONFIG_MAP_STR, "oauth2.token_source", "client_credentials",
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, token_source_str),
     "Source of the OAuth2 access token: client_credentials or metadata"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.metadata_url", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, metadata_url),
     "Metadata server URL used when token_source is 'metadata'"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.metadata_header", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_config, metadata_header),
     "Optional HTTP header (Name: Value) attached to metadata requests"
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
    cfg->enabled = FLB_FALSE;
    cfg->auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg->token_source = FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS;
    cfg->jwt_ttl = FLB_OAUTH2_DEFAULT_ASSERTION_TTL;
    cfg->refresh_skew = FLB_OAUTH2_DEFAULT_SKEW_SECS;
    cfg->timeout = 0;
    cfg->connect_timeout = 0;
    /* Initialize all pointer fields to NULL to avoid using uninitialized values */
    cfg->token_url = NULL;
    cfg->client_id = NULL;
    cfg->client_secret = NULL;
    cfg->scope = NULL;
    cfg->audience = NULL;
    cfg->resource = NULL;
    cfg->jwt_key_file = NULL;
    cfg->jwt_cert_file = NULL;
    cfg->jwt_aud = NULL;
    cfg->jwt_header = NULL;
    cfg->metadata_url = NULL;
    cfg->metadata_header = NULL;
    cfg->token_source_str = NULL;
}

/* flb_oauth2_token_source_parse converts a textual identifier to its enum value. */
int flb_oauth2_token_source_parse(const char *value, int *out)
{
    if (!value || !out) {
        return -1;
    }

    if (strcasecmp(value, "client_credentials") == 0) {
        *out = FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS;
        return 0;
    }

    if (strcasecmp(value, "metadata") == 0) {
        *out = FLB_OAUTH2_TOKEN_SOURCE_METADATA;
        return 0;
    }

    return -1;
}

/* flb_oauth2_config_resolve_token_source parses cfg->token_source_str into
 * cfg->token_source; no-op when NULL/empty. */
int flb_oauth2_config_resolve_token_source(struct flb_oauth2_config *cfg)
{
    int parsed;
    int ret;

    if (!cfg) {
        return -1;
    }

    if (!cfg->token_source_str || flb_sds_len(cfg->token_source_str) == 0) {
        return 0;
    }

    ret = flb_oauth2_token_source_parse(cfg->token_source_str, &parsed);
    if (ret != 0) {
        flb_error("[oauth2] invalid oauth2.token_source value '%s'",
                  cfg->token_source_str);
        return -1;
    }

    cfg->token_source = parsed;
    return 0;
}

/* oauth2_header_name_is_token reports whether c is a valid RFC7230 token
 * character, the only bytes permitted in an HTTP header field-name. */
static int oauth2_header_name_is_token(unsigned char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) {
        return FLB_TRUE;
    }

    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'':
    case '*': case '+': case '-': case '.': case '^': case '_':
    case '`': case '|': case '~':
        return FLB_TRUE;
    default:
        return FLB_FALSE;
    }
}

/* flb_oauth2_metadata_split_header splits "Name: Value" on the first colon,
 * restricting the field-name to RFC7230 token characters and rejecting any
 * control byte in the field-value. */
int flb_oauth2_metadata_split_header(const char *header,
                                     flb_sds_t *name_out,
                                     flb_sds_t *value_out)
{
    const char *colon;
    const char *name_start;
    const char *name_end;
    const char *value_start;
    const char *value_end;
    const char *p;
    char c;
    unsigned char uc;
    flb_sds_t name = NULL;
    flb_sds_t value = NULL;

    if (name_out) {
        *name_out = NULL;
    }
    if (value_out) {
        *value_out = NULL;
    }

    if (!header || !name_out || !value_out) {
        return -1;
    }

    colon = strchr(header, ':');
    if (!colon) {
        return -1;
    }

    name_start = header;
    name_end = colon;
    while (name_start < name_end) {
        c = *name_start;
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n' &&
            c != '\v' && c != '\f') {
            break;
        }
        name_start++;
    }
    while (name_end > name_start) {
        c = *(name_end - 1);
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n' &&
            c != '\v' && c != '\f') {
            break;
        }
        name_end--;
    }

    if (name_end <= name_start) {
        return -1;
    }

    value_start = colon + 1;
    value_end = value_start + strlen(value_start);
    while (value_start < value_end) {
        c = *value_start;
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n' &&
            c != '\v' && c != '\f') {
            break;
        }
        value_start++;
    }
    while (value_end > value_start) {
        c = *(value_end - 1);
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n' &&
            c != '\v' && c != '\f') {
            break;
        }
        value_end--;
    }

    if (value_end <= value_start) {
        return -1;
    }

    /* Field-name must be an RFC7230 token; any other byte (CTLs, separators,
     * whitespace) is rejected. This subsumes the CR/LF/NUL injection guard. */
    for (p = name_start; p < name_end; p++) {
        if (!oauth2_header_name_is_token((unsigned char) *p)) {
            return -1;
        }
    }

    /* Field-value may carry VCHAR, SP, HTAB and obs-text; reject every other
     * control byte (including CR/LF/NUL and DEL) to block header injection and
     * malformed bytes reaching the HTTP layer. */
    for (p = value_start; p < value_end; p++) {
        c = *p;
        uc = (unsigned char) c;
        if ((uc < 0x20 && uc != '\t') || uc == 0x7f) {
            return -1;
        }
    }

    name = flb_sds_create_len(name_start, (int)(name_end - name_start));
    if (!name) {
        flb_errno();
        return -1;
    }

    value = flb_sds_create_len(value_start, (int)(value_end - value_start));
    if (!value) {
        flb_errno();
        flb_sds_destroy(name);
        return -1;
    }

    *name_out = name;
    *value_out = value;
    return 0;
}

/* Wraps flb_uri_encode and additionally escapes '?', '&', '=' to prevent
 * extra params being injected into the metadata URL. */
static flb_sds_t oauth2_encode_query_value(const char *value, size_t len)
{
    size_t i;
    size_t base_len;
    flb_sds_t base;
    flb_sds_t out;
    flb_sds_t tmp;
    char c;

    base = flb_uri_encode(value, len);
    if (!base) {
        return NULL;
    }

    base_len = flb_sds_len(base);
    out = flb_sds_create_size(base_len * 3);
    if (!out) {
        flb_errno();
        flb_sds_destroy(base);
        return NULL;
    }

    for (i = 0; i < base_len; i++) {
        c = base[i];
        if (c == '?' || c == '&' || c == '=') {
            tmp = flb_sds_printf(&out, "%%%02X", (unsigned char) c);
        }
        else {
            tmp = flb_sds_cat(out, &c, 1);
        }
        if (!tmp) {
            flb_sds_destroy(base);
            flb_sds_destroy(out);
            return NULL;
        }
        out = tmp;
    }

    flb_sds_destroy(base);
    return out;
}

/* Appends URL-encoded query params to ctx->cfg.metadata_url. */
flb_sds_t flb_oauth2_metadata_build_url(struct flb_oauth2 *ctx)
{
    int first_param;
    flb_sds_t url = NULL;
    flb_sds_t encoded = NULL;
    flb_sds_t tmp = NULL;
    const char *base;

    if (!ctx) {
        return NULL;
    }

    base = ctx->cfg.metadata_url;
    if (!base) {
        return NULL;
    }

    url = flb_sds_create(base);
    if (!url) {
        flb_errno();
        return NULL;
    }

    if (!ctx->cfg.scope && !ctx->cfg.audience) {
        return url;
    }

    first_param = (strchr(base, '?') == NULL);

    if (ctx->cfg.scope && flb_sds_len(ctx->cfg.scope) > 0) {
        encoded = oauth2_encode_query_value(ctx->cfg.scope,
                                            flb_sds_len(ctx->cfg.scope));
        if (!encoded) {
            flb_sds_destroy(url);
            return NULL;
        }
        tmp = flb_sds_printf(&url, "%cscope=%s",
                             first_param ? '?' : '&', encoded);
        flb_sds_destroy(encoded);
        encoded = NULL;
        if (!tmp) {
            flb_sds_destroy(url);
            return NULL;
        }
        first_param = 0;
    }

    if (ctx->cfg.audience && flb_sds_len(ctx->cfg.audience) > 0) {
        encoded = oauth2_encode_query_value(ctx->cfg.audience,
                                            flb_sds_len(ctx->cfg.audience));
        if (!encoded) {
            flb_sds_destroy(url);
            return NULL;
        }
        tmp = flb_sds_printf(&url, "%caudience=%s",
                             first_param ? '?' : '&', encoded);
        flb_sds_destroy(encoded);
        encoded = NULL;
        if (!tmp) {
            flb_sds_destroy(url);
            return NULL;
        }
        first_param = 0;
    }

    return url;
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
    dst->token_source = src->token_source;

    if (src->refresh_skew > 0) {
        dst->refresh_skew = src->refresh_skew;
    }

    dst->timeout = src->timeout;
    dst->connect_timeout = src->connect_timeout;
    if (src->jwt_ttl > 0) {
        dst->jwt_ttl = src->jwt_ttl;
    }

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

    if (src->resource) {
        dst->resource = flb_sds_create(src->resource);
        if (!dst->resource) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->jwt_key_file) {
        dst->jwt_key_file =
            flb_sds_create(src->jwt_key_file);
        if (!dst->jwt_key_file) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->jwt_cert_file) {
        dst->jwt_cert_file =
            flb_sds_create(src->jwt_cert_file);
        if (!dst->jwt_cert_file) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->jwt_aud) {
        dst->jwt_aud =
            flb_sds_create(src->jwt_aud);
        if (!dst->jwt_aud) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->jwt_header) {
        dst->jwt_header = flb_sds_create(src->jwt_header);
        if (!dst->jwt_header) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->metadata_url) {
        dst->metadata_url = flb_sds_create(src->metadata_url);
        if (!dst->metadata_url) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->metadata_header) {
        dst->metadata_header = flb_sds_create(src->metadata_header);
        if (!dst->metadata_header) {
            flb_errno();
            flb_oauth2_config_destroy(dst);
            return -1;
        }
    }

    if (src->token_source_str) {
        dst->token_source_str = flb_sds_create(src->token_source_str);
        if (!dst->token_source_str) {
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
    flb_sds_destroy(cfg->resource);
    cfg->resource = NULL;
    flb_sds_destroy(cfg->jwt_key_file);
    cfg->jwt_key_file = NULL;
    flb_sds_destroy(cfg->jwt_cert_file);
    cfg->jwt_cert_file = NULL;
    flb_sds_destroy(cfg->jwt_aud);
    cfg->jwt_aud = NULL;
    flb_sds_destroy(cfg->jwt_header);
    cfg->jwt_header = NULL;
    flb_sds_destroy(cfg->metadata_url);
    cfg->metadata_url = NULL;
    flb_sds_destroy(cfg->metadata_header);
    cfg->metadata_header = NULL;
    flb_sds_destroy(cfg->token_source_str);
    cfg->token_source_str = NULL;
}

/* Caller must ensure the URL selected by ctx->cfg.token_source is non-NULL. */
static int oauth2_setup_upstream(struct flb_oauth2 *ctx,
                                 struct flb_config *config)
{
    int ret;
    const char *bind_url;
    char *prot = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;

    if (ctx->cfg.token_source == FLB_OAUTH2_TOKEN_SOURCE_METADATA) {
        bind_url = ctx->cfg.metadata_url;
    }
    else {
        bind_url = ctx->cfg.token_url;
    }

    ret = flb_utils_url_split(bind_url, &prot, &host, &port, &uri);
    if (ret == -1) {
        flb_error("[oauth2] invalid URL: %s", bind_url);
        goto error;
    }

    if (!prot || (strcmp(prot, "https") != 0 && strcmp(prot, "http") != 0)) {
        flb_error("[oauth2] invalid endpoint protocol: %s", bind_url);
        goto error;
    }

    if (!host) {
        flb_error("[oauth2] invalid URL host: %s", bind_url);
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
        ctx->u = flb_upstream_create_url(config, bind_url, FLB_IO_TLS, ctx->tls);
    }
    else {
        ctx->u = flb_upstream_create_url(config, bind_url, FLB_IO_TCP, NULL);
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
    int copy_len;
    int key_len;
    int val_len;
    char *end;
    int tokens_size = 32;
    const char *key;
    const char *val;
    unsigned long long parsed_expires_in;
    jsmn_parser parser;
    flb_sds_t new_access_token = NULL;
    flb_sds_t new_token_type = NULL;
    jsmntok_t *t;
    jsmntok_t *tokens;
    char tmp_num[32];
    uint64_t new_expires_in = 0;
    uint64_t skew;

    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tokens_size);
    if (!tokens) {
        flb_errno();
        return -1;
    }

    ret = jsmn_parse(&parser, json_data, json_size, tokens, tokens_size);
    if (ret <= 0) {
        flb_error("[oauth2] cannot parse payload (size=%zu)", json_size);
        flb_free(tokens);
        return -1;
    }

    t = &tokens[0];
    if (t->type != JSMN_OBJECT) {
        flb_error("[oauth2] invalid JSON response (size=%zu)", json_size);
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

        if (i + 1 >= ret) {
            break;
        }

        i++;
        t = &tokens[i];
        val = json_data + t->start;
        val_len = (t->end - t->start);

        if (key_cmp(key, key_len, "access_token") == 0) {
            if (new_access_token) {
                flb_sds_destroy(new_access_token);
            }

            new_access_token = flb_sds_create_len(val, val_len);
            if (!new_access_token) {
                flb_errno();
                break;
            }
        }
        else if (key_cmp(key, key_len, "token_type") == 0) {
            if (new_token_type) {
                flb_sds_destroy(new_token_type);
            }

            new_token_type = flb_sds_create_len(val, val_len);
            if (!new_token_type) {
                flb_errno();
                break;
            }
        }
        else if (key_cmp(key, key_len, "expires_in") == 0) {
            if (val_len <= 0 || val_len >= sizeof(tmp_num)) {
                break;
            }

            copy_len = val_len < (sizeof(tmp_num) - 1) ? val_len : (sizeof(tmp_num) - 1);
            strncpy(tmp_num, val, copy_len);
            tmp_num[copy_len] = '\0';

            if (tmp_num[0] == '-') {
                break;
            }

            errno = 0;
            parsed_expires_in = strtoull(tmp_num, &end, 10);

            if (errno != 0 || end == tmp_num || *end != '\0') {
                break;
            }

            new_expires_in = parsed_expires_in;
            new_expires_in -= (new_expires_in / 10);
        }
    }

    flb_free(tokens);

    if (!new_access_token) {
        flb_error("[oauth2] response missing 'access_token' field");
        flb_sds_destroy(new_token_type);
        return -1;
    }

    if (!new_token_type) {
        flb_error("[oauth2] response missing 'token_type' field");
        flb_sds_destroy(new_access_token);
        return -1;
    }

    skew = ctx->refresh_skew > 0 ? (uint64_t) ctx->refresh_skew : 0;

    if (new_expires_in <= skew) {
        flb_error("[oauth2] token rejected: effective lifetime "
                  "(%" PRIu64 "s, after 10%% safety margin) "
                  "is not greater than refresh_skew_seconds (%d); "
                  "reduce refresh_skew_seconds below %" PRIu64,
                  new_expires_in, ctx->refresh_skew, new_expires_in);
        flb_sds_destroy(new_access_token);
        flb_sds_destroy(new_token_type);
        return -1;
    }

    oauth2_reset_state(ctx);

    ctx->access_token = new_access_token;
    ctx->token_type = new_token_type;
    ctx->expires_in = new_expires_in;
    ctx->expires_at = time(NULL) + new_expires_in;

    return 0;
}

static flb_sds_t oauth2_append_kv(flb_sds_t buffer, const char *key,
                                  const char *value)
{
    flb_sds_t tmp;
    flb_sds_t result;

    if (!value) {
        return buffer;
    }

    tmp = flb_uri_encode(value, strlen(value));
    if (!tmp) {
        flb_errno();
        if (buffer) {
            flb_sds_destroy(buffer);
        }
        return NULL;
    }

    if (flb_sds_len(buffer) > 0) {
        result = flb_sds_cat(buffer, "&", 1);
        if (!result) {
            flb_sds_destroy(tmp);
            if (buffer) {
                flb_sds_destroy(buffer);
            }
            return NULL;
        }
        buffer = result;
    }

    result = flb_sds_cat(buffer, key, strlen(key));
    if (!result) {
        flb_sds_destroy(tmp);
        if (buffer) {
            flb_sds_destroy(buffer);
        }
        return NULL;
    }
    buffer = result;

    result = flb_sds_cat(buffer, "=", 1);
    if (!result) {
        flb_sds_destroy(tmp);
        if (buffer) {
            flb_sds_destroy(buffer);
        }
        return NULL;
    }
    buffer = result;

    result = flb_sds_cat(buffer, tmp, flb_sds_len(tmp));
    flb_sds_destroy(tmp);
    if (!result) {
        if (buffer) {
            flb_sds_destroy(buffer);
        }
        return NULL;
    }

    return result;
}

static int oauth2_base64_url_encode(const unsigned char *input, size_t input_size,
                                    flb_sds_t *output)
{
    int i;
    int ret;
    size_t olen;
    size_t encoded_size;
    unsigned char *encoded;

    if (!input || !output) {
        return -1;
    }

    encoded_size = ((input_size + 2) / 3) * 4 + 4;

    encoded = flb_malloc(encoded_size);
    if (!encoded) {
        flb_errno();
        return -1;
    }

    ret = flb_base64_encode(encoded, encoded_size - 1, &olen,
                            (unsigned char *) input, input_size);
    if (ret != 0) {
        flb_free(encoded);
        return -1;
    }

    for (i = 0; i < (int) olen && encoded[i] != '='; i++) {
        if (encoded[i] == '+') {
            encoded[i] = '-';
        }
        else if (encoded[i] == '/') {
            encoded[i] = '_';
        }
    }

    *output = flb_sds_create_len((char *) encoded, i);
    flb_free(encoded);

    if (!*output) {
        flb_errno();
        return -1;
    }

    return 0;
}

static int oauth2_private_key_jwt_thumbprint(const char *certificate_file,
                                             const char *header_name,
                                             flb_sds_t *thumbprint)
{
    int i;
    int ret;
    const EVP_MD *digest_type;
    char hex[EVP_MAX_MD_SIZE * 2 + 1];
    BIO *bio = NULL;
    X509 *cert = NULL;
    char *file_buf = NULL;
    size_t file_size;
    unsigned int digest_len = 0;
    unsigned char digest[EVP_MAX_MD_SIZE];

    ret = flb_utils_read_file((char *) certificate_file, &file_buf, &file_size);
    if (ret != 0 || !file_buf || file_size == 0) {
        flb_error("[oauth2] failed to read certificate file '%s'", certificate_file);
        return -1;
    }

    if (file_size > INT_MAX) {
        flb_error("[oauth2] certificate file '%s' is too large",
                  certificate_file);
        flb_free(file_buf);
        return -1;
    }

    bio = BIO_new_mem_buf(file_buf, (int) file_size);
    if (!bio) {
        flb_error("[oauth2] failed to initialize certificate buffer");
        flb_free(file_buf);
        return -1;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bio);
        bio = BIO_new_mem_buf(file_buf, (int) file_size);
        if (!bio) {
            flb_error("[oauth2] failed to reload certificate buffer");
            flb_free(file_buf);
            return -1;
        }
        cert = d2i_X509_bio(bio, NULL);
    }

    if (!cert) {
        flb_error("[oauth2] certificate '%s' is not valid PEM/DER X509",
                  certificate_file);
        BIO_free(bio);
        flb_free(file_buf);
        return -1;
    }

    digest_type = EVP_sha1();
    if (strcasecmp(header_name, "x5t#S256") == 0) {
        digest_type = EVP_sha256();
    }

    ret = X509_digest(cert, digest_type, digest, &digest_len);
    if (ret != 1 || digest_len == 0) {
        flb_error("[oauth2] failed to compute certificate thumbprint");
        X509_free(cert);
        BIO_free(bio);
        flb_free(file_buf);
        return -1;
    }

    if (strcasecmp(header_name, "x5t") == 0 ||
        strcasecmp(header_name, "x5t#S256") == 0) {
        ret = oauth2_base64_url_encode(digest, digest_len, thumbprint);
        if (ret != 0) {
            X509_free(cert);
            BIO_free(bio);
            flb_free(file_buf);
            return -1;
        }
    }
    else {
        for (i = 0; i < (int) digest_len; i++) {
            snprintf(&hex[i * 2], 3, "%02X", digest[i]);
        }
        hex[digest_len * 2] = '\0';

        *thumbprint = flb_sds_create(hex);
        if (!*thumbprint) {
            flb_errno();
            X509_free(cert);
            BIO_free(bio);
            flb_free(file_buf);
            return -1;
        }
    }

    X509_free(cert);
    BIO_free(bio);
    flb_free(file_buf);

    return 0;
}

static int oauth2_private_key_jwt_sign(const char *private_key_file,
                                       const char *data, size_t data_len,
                                       flb_sds_t *signature)
{
    int ret;
    char *key_buf = NULL;
    size_t key_size;
    size_t sig_len;
    unsigned char digest[32];
    unsigned char sig[4096];

    ret = flb_utils_read_file((char *) private_key_file, &key_buf, &key_size);
    if (ret != 0 || !key_buf || key_size == 0) {
        flb_error("[oauth2] failed to read private key file '%s'", private_key_file);
        return -1;
    }

    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char *) data, data_len,
                          digest, sizeof(digest));
    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_error("[oauth2] failed to hash JWT assertion payload");
        flb_free(key_buf);
        return -1;
    }

    sig_len = sizeof(sig);
    ret = flb_crypto_sign_simple(FLB_CRYPTO_PRIVATE_KEY,
                                 FLB_CRYPTO_PADDING_PKCS1,
                                 FLB_HASH_SHA256,
                                 (unsigned char *) key_buf, key_size,
                                 digest, sizeof(digest),
                                 sig, &sig_len);
    flb_free(key_buf);
    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_error("[oauth2] failed to sign JWT assertion");
        return -1;
    }

    return oauth2_base64_url_encode(sig, sig_len, signature);
}

static flb_sds_t oauth2_private_key_jwt_create_assertion(struct flb_oauth2 *ctx)
{
    int ret;
    int ttl;
    time_t now;
    char jti[FLB_OAUTH2_ASSERTION_UUID_LEN] = {0};
    const char *header_name;
    const char *audience;
    flb_sds_t thumbprint = NULL;
    flb_sds_t header_json = NULL;
    flb_sds_t payload_json = NULL;
    flb_sds_t header_b64 = NULL;
    flb_sds_t payload_b64 = NULL;
    flb_sds_t signing_input = NULL;
    flb_sds_t signature_b64 = NULL;
    flb_sds_t assertion = NULL;
    flb_sds_t tmp = NULL;

    if (!ctx->cfg.client_id || !ctx->cfg.jwt_key_file ||
        !ctx->cfg.jwt_cert_file) {
        flb_error("[oauth2] private_key_jwt requires client_id, "
                  "jwt_key_file and "
                  "jwt_cert_file");
        return NULL;
    }

    header_name = ctx->cfg.jwt_header ?
                  ctx->cfg.jwt_header :
                  FLB_OAUTH2_DEFAULT_ASSERTION_HEADER;
    audience = ctx->cfg.jwt_aud ?
               ctx->cfg.jwt_aud :
               ctx->cfg.token_url;
    ttl = ctx->cfg.jwt_ttl > 0 ?
          ctx->cfg.jwt_ttl :
          FLB_OAUTH2_DEFAULT_ASSERTION_TTL;

    if (flb_utils_uuid_v4_gen(jti) != 0) {
        flb_error("[oauth2] failed to generate JWT jti");
        return NULL;
    }

    ret = oauth2_private_key_jwt_thumbprint(
            ctx->cfg.jwt_cert_file,
            header_name, &thumbprint);
    if (ret != 0) {
        return NULL;
    }

    header_json = flb_sds_create_size(256);
    if (!header_json) {
        flb_errno();
        goto error;
    }
    tmp = flb_sds_printf(&header_json,
                         "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"%s\":\"%s\"}",
                         header_name, thumbprint);
    if (!tmp) {
        goto error;
    }
    header_json = tmp;

    now = time(NULL);
    payload_json = flb_sds_create_size(512);
    if (!payload_json) {
        flb_errno();
        goto error;
    }
    tmp = flb_sds_printf(&payload_json,
                         "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":\"%s\","
                         "\"iat\":%lu,\"exp\":%lu,\"jti\":\"%s\"}",
                         ctx->cfg.client_id, ctx->cfg.client_id, audience,
                         (unsigned long) now, (unsigned long) (now + ttl),
                         jti);
    if (!tmp) {
        goto error;
    }
    payload_json = tmp;

    ret = oauth2_base64_url_encode((unsigned char *) header_json,
                                   flb_sds_len(header_json), &header_b64);
    if (ret != 0) {
        goto error;
    }

    ret = oauth2_base64_url_encode((unsigned char *) payload_json,
                                   flb_sds_len(payload_json), &payload_b64);
    if (ret != 0) {
        goto error;
    }

    signing_input = flb_sds_create_size(flb_sds_len(header_b64) +
                                        flb_sds_len(payload_b64) + 2);
    if (!signing_input) {
        flb_errno();
        goto error;
    }

    tmp = flb_sds_printf(&signing_input, "%s.%s", header_b64, payload_b64);
    if (!tmp) {
        goto error;
    }
    signing_input = tmp;

    ret = oauth2_private_key_jwt_sign(ctx->cfg.jwt_key_file,
                                      signing_input, flb_sds_len(signing_input),
                                      &signature_b64);
    if (ret != 0) {
        goto error;
    }

    assertion = flb_sds_create_size(flb_sds_len(signing_input) +
                                    flb_sds_len(signature_b64) + 2);
    if (!assertion) {
        flb_errno();
        goto error;
    }

    tmp = flb_sds_printf(&assertion, "%s.%s", signing_input, signature_b64);
    if (!tmp) {
        goto error;
    }
    assertion = tmp;

    flb_sds_destroy(thumbprint);
    flb_sds_destroy(header_json);
    flb_sds_destroy(payload_json);
    flb_sds_destroy(header_b64);
    flb_sds_destroy(payload_b64);
    flb_sds_destroy(signing_input);
    flb_sds_destroy(signature_b64);

    return assertion;

error:
    flb_sds_destroy(assertion);
    flb_sds_destroy(signature_b64);
    flb_sds_destroy(signing_input);
    flb_sds_destroy(payload_b64);
    flb_sds_destroy(header_b64);
    flb_sds_destroy(payload_json);
    flb_sds_destroy(header_json);
    flb_sds_destroy(thumbprint);

    return NULL;
}

static flb_sds_t oauth2_build_body(struct flb_oauth2 *ctx)
{
    flb_sds_t body;
    flb_sds_t tmp;
    flb_sds_t assertion = NULL;

    if (ctx->payload_manual == FLB_TRUE && ctx->payload) {
        return flb_sds_create_len(ctx->payload, flb_sds_len(ctx->payload));
    }

    if ((ctx->cfg.auth_method == FLB_OAUTH2_AUTH_METHOD_BASIC ||
         ctx->cfg.auth_method == FLB_OAUTH2_AUTH_METHOD_POST) &&
        (!ctx->cfg.client_id || !ctx->cfg.client_secret)) {
        flb_error("[oauth2] auth method requires client_id and client_secret");
        return NULL;
    }

    body = flb_sds_create_size(128);
    if (!body) {
        return NULL;
    }

    tmp = oauth2_append_kv(body, "grant_type", "client_credentials");
    if (!tmp) {
        flb_sds_destroy(body);
        return NULL;
    }
    body = tmp;

    if (ctx->cfg.scope) {
        tmp = oauth2_append_kv(body, "scope", ctx->cfg.scope);
        if (!tmp) {
            flb_sds_destroy(body);
            return NULL;
        }
        body = tmp;
    }

    if (ctx->cfg.audience) {
        tmp = oauth2_append_kv(body, "audience", ctx->cfg.audience);
        if (!tmp) {
            flb_sds_destroy(body);
            return NULL;
        }
        body = tmp;
    }

    if (ctx->cfg.resource) {
        tmp = oauth2_append_kv(body, "resource", ctx->cfg.resource);
        if (!tmp) {
            flb_sds_destroy(body);
            return NULL;
        }
        body = tmp;
    }

    if (ctx->cfg.auth_method == FLB_OAUTH2_AUTH_METHOD_POST) {
        if (ctx->cfg.client_id) {
            tmp = oauth2_append_kv(body, "client_id", ctx->cfg.client_id);
            if (!tmp) {
                flb_sds_destroy(body);
                return NULL;
            }
            body = tmp;
        }

        if (ctx->cfg.client_secret) {
            tmp = oauth2_append_kv(body, "client_secret", ctx->cfg.client_secret);
            if (!tmp) {
                flb_sds_destroy(body);
                return NULL;
            }
            body = tmp;
        }
    }
    else if (ctx->cfg.auth_method == FLB_OAUTH2_AUTH_METHOD_PRIVATE_KEY_JWT) {
        if (ctx->cfg.client_id) {
            tmp = oauth2_append_kv(body, "client_id", ctx->cfg.client_id);
            if (!tmp) {
                flb_sds_destroy(body);
                return NULL;
            }
            body = tmp;
        }

        tmp = oauth2_append_kv(body, "client_assertion_type",
                               "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        if (!tmp) {
            flb_sds_destroy(body);
            return NULL;
        }
        body = tmp;

        assertion = oauth2_private_key_jwt_create_assertion(ctx);
        if (!assertion) {
            flb_sds_destroy(body);
            return NULL;
        }

        tmp = oauth2_append_kv(body, "client_assertion", assertion);
        flb_sds_destroy(assertion);
        if (!tmp) {
            flb_sds_destroy(body);
            return NULL;
        }
        body = tmp;
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

static int oauth2_client_credentials_refresh_locked(struct flb_oauth2 *ctx)
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

int flb_oauth2_metadata_refresh_locked(struct flb_oauth2 *ctx)
{
    int ret;
    int rc = -1;
    int port_n;
    int ipv6_enabled = FLB_FALSE;
    size_t b_sent = 0;
    flb_sds_t url = NULL;
    flb_sds_t header_name = NULL;
    flb_sds_t header_value = NULL;
    char *prot = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    struct flb_connection *u_conn = NULL;
    struct flb_http_client *c = NULL;

    if (!ctx) {
        return -1;
    }

    url = flb_oauth2_metadata_build_url(ctx);
    if (!url) {
        flb_error("[oauth2] could not build metadata URL");
        return -1;
    }

    ret = flb_utils_url_split(url, &prot, &host, &port, &uri);
    if (ret == -1 || !host || !uri) {
        flb_error("[oauth2] invalid metadata URL: %s", url);
        goto cleanup;
    }

    if (ctx->cfg.metadata_header) {
        ret = flb_oauth2_metadata_split_header(ctx->cfg.metadata_header,
                                               &header_name, &header_value);
        if (ret != 0) {
            flb_error("[oauth2] invalid metadata_header format "
                      "(expected 'Name: value')");
            goto cleanup;
        }
    }

    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_stream_enable_flags(&ctx->u->base, FLB_IO_IPV6);
        ipv6_enabled = FLB_TRUE;
        u_conn = flb_upstream_conn_get(ctx->u);
        if (!u_conn) {
            flb_error("[oauth2] could not get upstream connection for metadata");
            goto cleanup;
        }
    }

    /* When the metadata URL omits an explicit port, pass 0 so flb_http_client
     * derives the Host header port from the connected upstream (u->tcp_port:
     * 80 for http, 443 for https). Substituting ctx->port here would emit the
     * FLB_OAUTH2_PORT default (443) and mislabel a port-80 metadata request. */
    if (port) {
        port_n = atoi(port);
    }
    else {
        port_n = 0;
    }

    c = flb_http_client(u_conn, FLB_HTTP_GET, uri,
                        NULL, 0,
                        host, port_n,
                        NULL, 0);
    if (!c) {
        flb_error("[oauth2] error creating HTTP client for metadata");
        goto cleanup;
    }

    if (ctx->cfg.timeout > 0) {
        flb_http_set_response_timeout(c, ctx->cfg.timeout);
        flb_http_set_read_idle_timeout(c, ctx->cfg.timeout);
    }

    if (header_name && header_value) {
        ret = flb_http_add_header(c,
                                  header_name, flb_sds_len(header_name),
                                  header_value, flb_sds_len(header_value));
        if (ret != 0) {
            flb_error("[oauth2] could not add metadata header");
            goto cleanup;
        }
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[oauth2] metadata request failed, http_do=%i", ret);
        goto cleanup;
    }

    if (c->resp.status != 200) {
        flb_error("[oauth2] metadata server returned HTTP %d",
                  c->resp.status);
        goto cleanup;
    }

    if (c->resp.payload_size == 0) {
        flb_error("[oauth2] empty metadata response body");
        goto cleanup;
    }

    ret = flb_oauth2_parse_json_response(c->resp.payload,
                                         c->resp.payload_size, ctx);
    if (ret != 0) {
        goto cleanup;
    }

    flb_info("[oauth2] access token from metadata '%s:%s' retrieved",
             host,
             port ? port : (prot && strcmp(prot, "https") == 0 ? "443" : "80"));
    rc = 0;

cleanup:
    if (c) {
        flb_http_client_destroy(c);
    }
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }
    /* Keep FLB_IO_IPV6 sticky once the IPv6 failover has produced a working
     * connection: clear it only when the refresh failed (rc != 0), mirroring
     * oauth2_http_request(). On the success-after-retry path the flag stays
     * enabled so the next refresh reuses the address family that worked. No
     * unit test asserts this branch: the loopback mock always satisfies the
     * first IPv4 conn_get, so ipv6_enabled never becomes true without a
     * dual-stack failover that the in-process fixture cannot reproduce. */
    if (ipv6_enabled && rc != 0) {
        flb_stream_disable_flags(&ctx->u->base, FLB_IO_IPV6);
    }
    flb_sds_destroy(header_name);
    flb_sds_destroy(header_value);
    flb_free(prot);
    flb_free(host);
    flb_free(port);
    flb_free(uri);
    flb_sds_destroy(url);

    return rc;
}

int flb_oauth2_dispatch_refresh_locked(struct flb_oauth2 *ctx)
{
    if (!ctx) {
        return -1;
    }

    switch (ctx->cfg.token_source) {
    case FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS:
        return oauth2_client_credentials_refresh_locked(ctx);
    case FLB_OAUTH2_TOKEN_SOURCE_METADATA:
        return flb_oauth2_metadata_refresh_locked(ctx);
    default:
        flb_error("[oauth2] invalid token_source enum value");
        return -1;
    }
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
    cfg.enabled = FLB_TRUE;
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

    /* Manual cleanup: flb_oauth2_destroy below assumes ctx->lock is initialized. */
    ret = flb_lock_init(&ctx->lock);
    if (ret != 0) {
        flb_oauth2_config_destroy(&ctx->cfg);
        flb_free(ctx);
        return NULL;
    }

    if (flb_oauth2_config_resolve_token_source(&ctx->cfg) != 0) {
        flb_oauth2_destroy(ctx);
        return NULL;
    }

    if (ctx->cfg.token_source != FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS &&
        ctx->cfg.token_source != FLB_OAUTH2_TOKEN_SOURCE_METADATA) {
        flb_error("[oauth2] invalid token_source value: %d",
                  ctx->cfg.token_source);
        flb_oauth2_destroy(ctx);
        return NULL;
    }

    if (ctx->cfg.token_source == FLB_OAUTH2_TOKEN_SOURCE_METADATA) {
        if (!ctx->cfg.metadata_url) {
            flb_error("[oauth2] metadata_url is not set");
            flb_oauth2_destroy(ctx);
            return NULL;
        }
    }
    else {
        if (!ctx->cfg.token_url) {
            flb_error("[oauth2] token_url is not set");
            flb_oauth2_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->cfg.auth_method == FLB_OAUTH2_AUTH_METHOD_PRIVATE_KEY_JWT) {
        if (!ctx->cfg.client_id ||
            !ctx->cfg.jwt_key_file ||
            !ctx->cfg.jwt_cert_file) {
            flb_error("[oauth2] private_key_jwt requires client_id, "
                      "jwt_key_file and "
                      "jwt_cert_file");
            flb_oauth2_destroy(ctx);
            return NULL;
        }
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

    ret = oauth2_setup_upstream(ctx, config);
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
        ret = flb_oauth2_dispatch_refresh_locked(ctx);
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
    if (!config_map) {
        flb_error("[oauth2] error loading OAuth2 config map");
        return NULL;
    }

    return config_map;
}
