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

#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_gcp_auth.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_unescape.h>

#include <monkey/mk_core.h>

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/*
 * Context-aware logging: prepend the per-instance prefix ("[gcp_auth]" or
 * "[gcp_auth:<name>]") so messages can be attributed to a plugin instance.
 */
#define gcp_log_error(ctx, fmt, ...) \
    flb_error("%s " fmt, (ctx)->log_prefix, ##__VA_ARGS__)
#define gcp_log_warn(ctx, fmt, ...) \
    flb_warn("%s " fmt, (ctx)->log_prefix, ##__VA_ARGS__)
#define gcp_log_info(ctx, fmt, ...) \
    flb_info("%s " fmt, (ctx)->log_prefix, ##__VA_ARGS__)
#define gcp_log_debug(ctx, fmt, ...) \
    flb_debug("%s " fmt, (ctx)->log_prefix, ##__VA_ARGS__)

static int gcp_key_cmp(const char *str, int len, const char *cmp)
{
    if (strlen(cmp) != (size_t) len) {
        return -1;
    }

    return strncasecmp(str, cmp, len);
}

/* Replaces *dst with a copy of the given bytes (a repeated JSON key wins) */
static int gcp_set_sds(flb_sds_t *dst, const char *val, int len)
{
    flb_sds_t tmp;

    tmp = flb_sds_create_len(val, len);
    if (!tmp) {
        return -1;
    }

    if (*dst) {
        flb_sds_destroy(*dst);
    }
    *dst = tmp;

    return 0;
}

static flb_sds_t gcp_sds_dup(const char *str)
{
    if (!str) {
        return NULL;
    }

    return flb_sds_create(str);
}

/* Returns the value of a top-level key of a JSON object. The key must match
 * exactly; values and nested keys are never matched. Kept local so this
 * helper does not depend on the AWS library. */
static flb_sds_t gcp_json_get_val(const char *response, size_t response_len,
                                  const char *key)
{
    int i;
    int j;
    int ret;
    int count;
    int tok_size = 50;
    size_t key_len;
    void *tmp_tokens;
    jsmn_parser parser;
    jsmntok_t *tokens;
    const jsmntok_t *k;
    const jsmntok_t *v;
    flb_sds_t value = NULL;

    if (!response || response_len == 0 || !key) {
        return NULL;
    }

    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_errno();
        return NULL;
    }

    jsmn_init(&parser);
    ret = jsmn_parse(&parser, response, response_len, tokens, tok_size);
    while (ret == JSMN_ERROR_NOMEM) {
        if (tok_size > INT_MAX / 2) {
            flb_free(tokens);
            return NULL;
        }

        tmp_tokens = flb_realloc(tokens, sizeof(jsmntok_t) * tok_size * 2);
        if (!tmp_tokens) {
            flb_errno();
            flb_free(tokens);
            return NULL;
        }
        tokens = tmp_tokens;
        tok_size *= 2;
        jsmn_init(&parser);
        ret = jsmn_parse(&parser, response, response_len, tokens, tok_size);
    }

    if (ret < 1 || tokens[0].type != JSMN_OBJECT) {
        flb_free(tokens);
        flb_debug("[gcp_auth] unable to parse API response, "
                  "response is not a valid JSON object");
        return NULL;
    }

    count = ret;
    key_len = strlen(key);

    /* walk the top-level key/value pairs, skipping the span of each value */
    i = 1;
    while (i < count - 1) {
        k = &tokens[i];
        v = &tokens[i + 1];

        if (k->type == JSMN_STRING &&
            (size_t) (k->end - k->start) == key_len &&
            strncmp(&response[k->start], key, key_len) == 0) {
            value = flb_sds_create_len(&response[v->start], v->end - v->start);
            if (!value) {
                flb_errno();
            }
            break;
        }

        j = i + 2;
        while (j < count && tokens[j].start < v->end) {
            j++;
        }
        i = j;
    }

    flb_free(tokens);
    return value;
}

/* Stores the value of a known credentials key; unknown keys are ignored. Returns -1
 * if a copy could not be made. */
static int gcp_credentials_set_field(struct flb_gcp_credentials *c,
                                     const char *key, int key_len,
                                     const char *val, int val_len)
{
    int len;
    flb_sds_t tmp;
    flb_sds_t unescaped;

    if (gcp_key_cmp(key, key_len, "type") == 0) {
        return gcp_set_sds(&c->type, val, val_len);
    }
    if (gcp_key_cmp(key, key_len, "project_id") == 0) {
        return gcp_set_sds(&c->project_id, val, val_len);
    }
    if (gcp_key_cmp(key, key_len, "private_key_id") == 0) {
        return gcp_set_sds(&c->private_key_id, val, val_len);
    }
    if (gcp_key_cmp(key, key_len, "private_key") == 0) {
        tmp = flb_sds_create_len(val, val_len);
        if (!tmp) {
            return -1;
        }
        len = flb_sds_len(tmp);
        unescaped = flb_sds_create_size(len);
        if (!unescaped) {
            flb_errno();
            flb_sds_destroy(tmp);
            return -1;
        }
        flb_unescape_string(tmp, len, &unescaped);
        flb_sds_destroy(tmp);
        if (c->private_key) {
            flb_sds_destroy(c->private_key);
        }
        c->private_key = unescaped;
        return 0;
    }
    if (gcp_key_cmp(key, key_len, "client_email") == 0) {
        return gcp_set_sds(&c->client_email, val, val_len);
    }
    if (gcp_key_cmp(key, key_len, "client_id") == 0) {
        return gcp_set_sds(&c->client_id, val, val_len);
    }
    if (gcp_key_cmp(key, key_len, "auth_uri") == 0) {
        return gcp_set_sds(&c->auth_uri, val, val_len);
    }
    if (gcp_key_cmp(key, key_len, "token_uri") == 0) {
        return gcp_set_sds(&c->token_uri, val, val_len);
    }

    return 0;
}

/* credential parse and oauth helpers based on bigquery/stackdriver style */
int flb_gcp_credentials_read(const char *path, struct flb_gcp_credentials *c)
{
    int i, j, ret, count;
    int tok_size = 32;
    size_t content_len;
    char *buf;
    void *tmp_tokens;
    struct stat st;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *v;
    jsmntok_t *tokens;

    if (!path || !c) {
        return -1;
    }

    ret = stat(path, &st);
    if (ret == -1) {
        flb_errno();
        flb_error("[gcp_auth] cannot open credentials file: %s", path);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_error("[gcp_auth] credentials file is not a valid file: %s", path);
        return -1;
    }

    buf = mk_file_to_buffer(path);
    if (!buf) {
        flb_error("[gcp_auth] error reading credentials file: %s", path);
        return -1;
    }

    /* the buffer is NUL terminated: parse what was actually read */
    content_len = strlen(buf);

    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_free(buf);
        return -1;
    }

    ret = jsmn_parse(&parser, buf, content_len, tokens, tok_size);
    while (ret == JSMN_ERROR_NOMEM) {
        if (tok_size > INT_MAX / 2) {
            flb_error("[gcp_auth] credentials file is too large: %s", path);
            flb_free(buf);
            flb_free(tokens);
            return -1;
        }

        tmp_tokens = flb_realloc(tokens, sizeof(jsmntok_t) * tok_size * 2);
        if (!tmp_tokens) {
            flb_errno();
            flb_free(buf);
            flb_free(tokens);
            return -1;
        }
        tokens = tmp_tokens;
        tok_size *= 2;
        jsmn_init(&parser);
        ret = jsmn_parse(&parser, buf, content_len, tokens, tok_size);
    }

    if (ret <= 0) {
        flb_error("[gcp_auth] invalid JSON credentials file: %s", path);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    t = &tokens[0];
    if (t->type != JSMN_OBJECT) {
        flb_error("[gcp_auth] invalid JSON map on file: %s", path);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    /* walk the top-level key/value pairs, skipping the whole span of each value */
    count = ret;
    i = 1;
    while (i < count - 1) {
        t = &tokens[i];
        v = &tokens[i + 1];

        if (t->type == JSMN_STRING && t->start >= 0 && t->end >= 0 &&
            v->start >= 0 && v->end >= 0) {
            ret = gcp_credentials_set_field(c, buf + t->start, t->end - t->start,
                                            buf + v->start, v->end - v->start);
            if (ret != 0) {
                flb_free(buf);
                flb_free(tokens);
                return -1;
            }
        }

        j = i + 2;
        while (j < count && tokens[j].start < v->end) {
            j++;
        }
        i = j;
    }

    flb_free(buf);
    flb_free(tokens);

    if (!c->private_key) {
        flb_error("[gcp_auth] no private key");
        return -1;
    }

    return c->client_email ? 0 : -1;
}

void flb_gcp_credentials_destroy(struct flb_gcp_credentials *c)
{
    if (!c) {
        return;
    }

    if (c->type) {
        flb_sds_destroy(c->type);
    }
    if (c->project_id) {
        flb_sds_destroy(c->project_id);
    }
    if (c->private_key_id) {
        flb_sds_destroy(c->private_key_id);
    }
    if (c->private_key) {
        flb_sds_destroy(c->private_key);
    }
    if (c->client_email) {
        flb_sds_destroy(c->client_email);
    }
    if (c->client_id) {
        flb_sds_destroy(c->client_id);
    }
    if (c->auth_uri) {
        flb_sds_destroy(c->auth_uri);
    }
    if (c->token_uri) {
        flb_sds_destroy(c->token_uri);
    }

    flb_free(c);
}

static int gcp_jwt_base64_url_encode(unsigned char *out_buf, size_t out_size,
                                     unsigned char *in_buf, size_t in_size,
                                     size_t *olen)
{
    size_t i;
    size_t len;
    int result;

    if (!out_buf || !in_buf || !olen || out_size < 2) {
        return -1;
    }

    result = flb_base64_encode((unsigned char *) out_buf, out_size, &len,
                               in_buf, in_size);
    if (result != 0) {
        return -1;
    }
    for (i = 0; i < len && out_buf[i] != '='; i++) {
        if (out_buf[i] == '+') {
            out_buf[i] = '-';
        }
        else if (out_buf[i] == '/') {
            out_buf[i] = '_';
        }
    }
    out_buf[i] = '\0';
    *olen = i;
    return 0;
}

int flb_gcp_jwt_encode(const char *payload, const char *secret,
                       char **out_signature, size_t *out_size)
{
    int ret;
    size_t header_len;
    size_t payload_len;
    size_t secret_len;
    size_t input_len;
    size_t encoded_units;
    size_t buf_size;
    size_t olen, sig_len;
    char *buf;
    char *sigd;
    char *headers = "{\"alg\": \"RS256\", \"typ\": \"JWT\"}";
    unsigned char sha256_buf[32] = {0};
    flb_sds_t out;
    flb_sds_t tmp;
    unsigned char sig[256] = {0};

    if (!payload || !secret || !out_signature || !out_size) {
        return -1;
    }

    out = NULL;
    sigd = NULL;
    header_len = strlen(headers);
    payload_len = strlen(payload);
    secret_len = strlen(secret);
    input_len = header_len > payload_len ? header_len : payload_len;
    if (input_len > ((size_t) -1) - 2) {
        return -1;
    }

    encoded_units = (input_len + 2) / 3;
    if (encoded_units > (((size_t) -1) - 1) / 4) {
        return -1;
    }
    buf_size = (encoded_units * 4) + 1;
    buf = flb_malloc(buf_size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    ret = gcp_jwt_base64_url_encode((unsigned char *) buf, buf_size,
                                    (unsigned char *) headers,
                                    header_len, &olen);
    if (ret != 0) {
        goto error;
    }

    out = flb_sds_create_size(2048);
    if (!out) {
        flb_errno();
        goto error;
    }
    tmp = flb_sds_cat(out, buf, olen);
    if (!tmp) {
        goto error;
    }
    out = tmp;

    tmp = flb_sds_cat(out, ".", 1);
    if (!tmp) {
        goto error;
    }
    out = tmp;

    ret = gcp_jwt_base64_url_encode((unsigned char *) buf, buf_size,
                                    (unsigned char *) payload,
                                    payload_len, &olen);
    if (ret != 0) {
        goto error;
    }
    tmp = flb_sds_cat(out, buf, olen);
    if (!tmp) {
        goto error;
    }
    out = tmp;

    ret = flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) out,
                          flb_sds_len(out), sha256_buf, sizeof(sha256_buf));
    if (ret != FLB_CRYPTO_SUCCESS) {
        goto error;
    }

    sig_len = sizeof(sig);
    ret = flb_crypto_sign_simple(FLB_CRYPTO_PRIVATE_KEY, FLB_CRYPTO_PADDING_PKCS1,
                                 FLB_HASH_SHA256, (unsigned char *) secret,
                                 secret_len + 1, sha256_buf, sizeof(sha256_buf),
                                 sig, &sig_len);
    if (ret != FLB_CRYPTO_SUCCESS) {
        goto error;
    }

    sigd = flb_malloc(2048);
    if (!sigd) {
        flb_errno();
        goto error;
    }
    ret = gcp_jwt_base64_url_encode((unsigned char *) sigd, 2048, sig, sig_len,
                                    &olen);
    if (ret != 0) {
        goto error;
    }

    tmp = flb_sds_cat(out, ".", 1);
    if (!tmp) {
        goto error;
    }
    out = tmp;

    tmp = flb_sds_cat(out, sigd, olen);
    if (!tmp) {
        goto error;
    }
    out = tmp;

    *out_signature = out;
    *out_size = flb_sds_len(out);
    flb_free(buf);
    flb_free(sigd);

    return 0;

error:
    flb_free(buf);
    flb_free(sigd);
    if (out) {
        flb_sds_destroy(out);
    }

    return -1;
}

static int gcp_fetch_metadata_token(struct flb_gcp_auth *ctx, flb_sds_t *payload)
{
    int ret;
    int result;
    size_t bytes_sent;
    flb_sds_t tmp;
    struct flb_connection *connection;
    struct flb_http_client *client;

    if (ctx->metadata_fetch) {
        return ctx->metadata_fetch(ctx->metadata_fetch_data, payload);
    }

    connection = flb_upstream_conn_get(ctx->metadata_u);
    if (!connection) {
        gcp_log_error(ctx, "failed to connect to metadata server at '%s'; "
                      "provide google_service_credentials when not running on GCE/GKE",
                      ctx->metadata_server);
        return -1;
    }

    client = flb_http_client(connection, FLB_HTTP_GET,
                             FLB_GCP_METADATA_TOKEN_URI,
                             "", 0, NULL, 0, NULL, 0);
    if (!client) {
        flb_upstream_conn_release(connection);
        return -1;
    }

    flb_http_buffer_size(client, FLB_GCP_METADATA_TOKEN_SIZE_MAX);
    flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(client, "Metadata-Flavor", 15, "Google", 6);

    ret = flb_http_do(client, &bytes_sent);
    if (ret != 0) {
        gcp_log_warn(ctx, "metadata token request failed: http_do=%i", ret);
        result = -1;
    }
    else if (client->resp.status == 200) {
        tmp = flb_sds_copy(*payload, client->resp.payload,
                           client->resp.payload_size);
        if (tmp) {
            *payload = tmp;
            result = 0;
        }
        else {
            result = -1;
        }
    }
    else {
        gcp_log_warn(ctx, "metadata token request failed with "
                     "status=%i response='%.*s'",
                     client->resp.status,
                     (int) client->resp.payload_size,
                     client->resp.payload ? client->resp.payload : "");
        result = -1;
    }

    flb_http_client_destroy(client);
    flb_upstream_conn_release(connection);

    return result;
}

static int gcp_get_metadata_token(struct flb_gcp_auth *ctx)
{
    int ret;
    flb_sds_t payload;

    payload = flb_sds_create_size(FLB_GCP_METADATA_TOKEN_SIZE_MAX);
    if (!payload) {
        return -1;
    }

    ret = gcp_fetch_metadata_token(ctx, &payload);
    if (ret == 0) {
        ret = flb_oauth2_parse_json_response(payload, flb_sds_len(payload),
                                             ctx->o);
    }
    flb_sds_destroy(payload);

    if (ret != 0) {
        gcp_log_error(ctx, "could not retrieve a metadata server token");
        return -1;
    }

    ctx->o->expires_at = time(NULL) + ctx->o->expires_in;
    return 0;
}

int flb_gcp_auth_build_jwt_claim(struct flb_gcp_auth *ctx, time_t issued,
                                 char *buf, size_t size)
{
    int len;
    time_t expires;

    if (!ctx || !ctx->credentials || !buf || size == 0) {
        return -1;
    }

    expires = issued + FLB_GCP_TOKEN_REFRESH;
    len = snprintf(buf, size,
                   "{\"iss\": \"%s\", \"scope\": \"%s\", \"aud\": \"%s\", "
                   "\"exp\": %llu, \"iat\": %llu}",
                   ctx->credentials->client_email, ctx->scope, FLB_GCP_AUTH_URL,
                   (unsigned long long) expires, (unsigned long long) issued);
    if (len < 0 || (size_t) len >= size) {
        return -1;
    }

    return 0;
}

static int gcp_get_oauth2_token(struct flb_gcp_auth *ctx)
{
    int ret;
    char *sig_data;
    size_t sig_size;
    char payload[1024];

    flb_oauth2_payload_clear(ctx->o);
    if (ctx->metadata_server_auth == FLB_TRUE) {
        return gcp_get_metadata_token(ctx);
    }

    ret = flb_gcp_auth_build_jwt_claim(ctx, time(NULL), payload, sizeof(payload));
    if (ret != 0) {
        return -1;
    }

    ret = flb_gcp_jwt_encode(payload, ctx->credentials->private_key,
                             &sig_data, &sig_size);
    if (ret != 0) {
        gcp_log_error(ctx, "failed to sign the JWT assertion");
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o, "grant_type", -1,
                                    "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer", -1);
    if (ret == -1) {
        flb_sds_destroy(sig_data);
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o, "assertion", -1, sig_data, sig_size);
    flb_sds_destroy(sig_data);
    if (ret == -1 || !flb_oauth2_token_get(ctx->o)) {
        return -1;
    }

    return 0;
}

/* The platform rotates this file (e.g. kubelet projected token); read fresh, never cache. */
int flb_gcp_read_identity_token(const char *path, flb_sds_t *out_token)
{
    char *buf;
    size_t len;
    flb_sds_t token;

    if (!path || !out_token) {
        return -1;
    }

    buf = mk_file_to_buffer(path);
    if (!buf) {
        flb_error("[gcp_auth] could not read identity token file: %s", path);
        return -1;
    }

    len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                       buf[len - 1] == ' ' || buf[len - 1] == '\t')) {
        len--;
    }

    if (len == 0) {
        flb_error("[gcp_auth] identity token file is empty: %s", path);
        flb_free(buf);
        return -1;
    }

    token = flb_sds_create_len(buf, len);
    flb_free(buf);
    if (!token) {
        return -1;
    }

    *out_token = token;
    return 0;
}

/* Escapes content only; the caller supplies the surrounding quotes. */
static flb_sds_t gcp_json_escape(const char *str, size_t len)
{
    flb_sds_t out;
    flb_sds_t ret;

    out = flb_sds_create_size(len + 16);
    if (!out) {
        return NULL;
    }

    ret = flb_sds_cat_utf8(&out, str, (int) len);
    if (!ret) {
        flb_sds_destroy(out);
        return NULL;
    }

    return ret;
}

/* Days-from-civil (Howard Hinnant): portable UTC broken-down time to epoch,
 * avoiding non-portable timegm()/strptime() (this also builds on Windows). */
time_t flb_gcp_utc_to_epoch(int year, int mon, int mday,
                            int hour, int min, int sec)
{
    long y = year;
    long era;
    long yoe;
    long doy;
    long doe;
    long days;

    y -= (mon <= 2);
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (mon + (mon > 2 ? -3 : 9)) + 2) / 5 + mday - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    days = era * 146097 + doe - 719468;

    return (time_t) days * 86400 + hour * 3600 + min * 60 + sec;
}

/* Derive expiry from the server-stated lifetime (STS "expires_in" / IAM
 * "expireTime") minus a safety margin; fall back to FLB_GCP_TOKEN_REFRESH.
 * A NULL iam_payload means no service account impersonation. */
time_t flb_gcp_federation_token_expiry(time_t now,
                                       const char *sts_payload, size_t sts_size,
                                       const char *iam_payload, size_t iam_size)
{
    int y, mo, d, h, mi, s;
    long secs;
    time_t expiry = 0;
    flb_sds_t val;

    if (iam_payload) {
        val = gcp_json_get_val(iam_payload, iam_size, "expireTime");
        if (val) {
            if (sscanf(val, "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) == 6) {
                expiry = flb_gcp_utc_to_epoch(y, mo, d, h, mi, s);
            }
            flb_sds_destroy(val);
        }
    }
    else if (sts_payload) {
        val = gcp_json_get_val(sts_payload, sts_size, "expires_in");
        if (val) {
            secs = atol(val);
            if (secs > 0) {
                expiry = now + (time_t) secs;
            }
            flb_sds_destroy(val);
        }
    }

    if (expiry <= now) {
        return now + FLB_GCP_TOKEN_REFRESH;
    }

    expiry -= FLB_GCP_TOKEN_EXPIRY_SAFETY;
    if (expiry <= now) {
        expiry = now + 1;
    }

    return expiry;
}

/* Exchange the OIDC subject token at Google STS, optionally impersonating a
 * service account via IAM Credentials. Without impersonation the STS token is
 * used directly, so the configured scope is requested from STS; with
 * impersonation STS only needs cloud-platform and the configured scope is
 * requested from generateAccessToken.
 * https://cloud.google.com/iam/docs/workload-identity-federation */
static int gcp_exchange_identity_federation_token(struct flb_gcp_auth *ctx)
{
    int ret = -1;
    int http_ret;
    size_t b_sent;
    time_t now;
    flb_sds_t subject_token = NULL;
    flb_sds_t sts_body = NULL;
    flb_sds_t federated_token = NULL;
    flb_sds_t iam_url = NULL;
    flb_sds_t iam_body = NULL;
    flb_sds_t auth_header = NULL;
    flb_sds_t new_token = NULL;
    flb_sds_t audience_esc = NULL;
    flb_sds_t token_type_esc = NULL;
    flb_sds_t subject_token_esc = NULL;
    flb_sds_t scope_esc = NULL;
    flb_sds_t sts_scope_esc = NULL;
    struct flb_connection *sts_conn = NULL;
    struct flb_connection *iam_conn = NULL;
    struct flb_http_client *sts_c = NULL;
    struct flb_http_client *iam_c = NULL;

    if (flb_gcp_read_identity_token(ctx->identity_token_file,
                                    &subject_token) != 0) {
        gcp_log_error(ctx, "failed to read the identity token file");
        return -1;
    }

    /* JSON-escape user-controlled values before embedding them in the request */
    audience_esc = gcp_json_escape(ctx->sts_audience,
                                   flb_sds_len(ctx->sts_audience));
    token_type_esc = gcp_json_escape(ctx->subject_token_type,
                                     flb_sds_len(ctx->subject_token_type));
    subject_token_esc = gcp_json_escape(subject_token,
                                        flb_sds_len(subject_token));
    if (!audience_esc || !token_type_esc || !subject_token_esc) {
        goto cleanup;
    }

    /* direct resource access: the STS token carries the configured scope */
    if (!ctx->google_service_account) {
        sts_scope_esc = gcp_json_escape(ctx->scope, flb_sds_len(ctx->scope));
        if (!sts_scope_esc) {
            goto cleanup;
        }
    }

    sts_body = flb_sds_create_size(flb_sds_len(subject_token_esc) + 512);
    if (!sts_body) {
        goto cleanup;
    }
    if (!flb_sds_printf(&sts_body,
                        "{\"audience\":\"%s\","
                        "\"grantType\":\"%s\","
                        "\"requestedTokenType\":\"%s\","
                        "\"scope\":\"%s\","
                        "\"subjectTokenType\":\"%s\","
                        "\"subjectToken\":\"%s\"}",
                        audience_esc,
                        FLB_GCP_STS_GRANT_TYPE,
                        FLB_GCP_STS_REQUESTED_TOKEN_TYPE,
                        sts_scope_esc ? sts_scope_esc : FLB_GCP_STS_SCOPE,
                        token_type_esc,
                        subject_token_esc)) {
        goto cleanup;
    }

    /* token lifetimes are relative to the moment the request is sent */
    now = time(NULL);

    sts_conn = flb_upstream_conn_get(ctx->sts_u);
    if (!sts_conn) {
        gcp_log_error(ctx, "failed to connect to Google STS");
        goto cleanup;
    }

    sts_c = flb_http_client(sts_conn, FLB_HTTP_POST, FLB_GCP_STS_TOKEN_ENDPOINT,
                            sts_body, flb_sds_len(sts_body), NULL, 0, NULL, 0);
    if (!sts_c) {
        goto cleanup;
    }
    flb_http_buffer_size(sts_c, FLB_GCP_TOKEN_RESPONSE_SIZE_MAX);
    flb_http_add_header(sts_c, "Content-Type", 12, "application/json", 16);

    http_ret = flb_http_do(sts_c, &b_sent);
    if (http_ret != 0 || sts_c->resp.status != 200) {
        gcp_log_error(ctx, "Google STS token exchange failed "
                      "(http_do=%i status=%i): %s",
                      http_ret, sts_c->resp.status,
                      sts_c->resp.payload ? sts_c->resp.payload : "");
        goto cleanup;
    }

    federated_token = gcp_json_get_val(sts_c->resp.payload,
                                       sts_c->resp.payload_size,
                                       "access_token");
    if (!federated_token) {
        gcp_log_error(ctx, "could not extract federated access token "
                      "from STS response");
        goto cleanup;
    }

    if (!ctx->google_service_account) {
        new_token = flb_sds_create(federated_token);
        if (!new_token) {
            goto cleanup;
        }
    }
    else {
        /* Impersonate the target service account via IAM Credentials */
        iam_url = flb_sds_create_size(256);
        if (!iam_url) {
            goto cleanup;
        }
        if (!flb_sds_printf(&iam_url, FLB_GCP_GEN_ACCESS_TOKEN_ENDPOINT,
                            ctx->google_service_account)) {
            goto cleanup;
        }

        auth_header = flb_sds_create_size(flb_sds_len(federated_token) +
                                          sizeof("Bearer "));
        if (!auth_header) {
            goto cleanup;
        }
        if (!flb_sds_printf(&auth_header, "Bearer %s", federated_token)) {
            goto cleanup;
        }

        scope_esc = gcp_json_escape(ctx->scope, flb_sds_len(ctx->scope));
        if (!scope_esc) {
            goto cleanup;
        }
        iam_body = flb_sds_create_size(flb_sds_len(scope_esc) + 32);
        if (!iam_body) {
            goto cleanup;
        }
        if (!flb_sds_printf(&iam_body, "{\"scope\": [\"%s\"]}", scope_esc)) {
            goto cleanup;
        }

        iam_conn = flb_upstream_conn_get(ctx->iam_u);
        if (!iam_conn) {
            gcp_log_error(ctx, "failed to connect to Google IAM Credentials");
            goto cleanup;
        }

        iam_c = flb_http_client(iam_conn, FLB_HTTP_POST, iam_url,
                                iam_body, flb_sds_len(iam_body), NULL, 0, NULL, 0);
        if (!iam_c) {
            goto cleanup;
        }
        flb_http_buffer_size(iam_c, FLB_GCP_TOKEN_RESPONSE_SIZE_MAX);
        flb_http_add_header(iam_c, "Authorization", 13,
                            auth_header, flb_sds_len(auth_header));
        flb_http_add_header(iam_c, "Content-Type", 12, "application/json", 16);

        http_ret = flb_http_do(iam_c, &b_sent);
        if (http_ret != 0 || iam_c->resp.status != 200) {
            gcp_log_error(ctx, "IAM generateAccessToken failed "
                          "(http_do=%i status=%i): %s",
                          http_ret, iam_c->resp.status,
                          iam_c->resp.payload ? iam_c->resp.payload : "");
            goto cleanup;
        }

        new_token = gcp_json_get_val(iam_c->resp.payload,
                                     iam_c->resp.payload_size,
                                     "accessToken");
        if (!new_token) {
            gcp_log_error(ctx, "could not extract accessToken from "
                          "IAM response");
            goto cleanup;
        }
    }

    if (ctx->federation_token) {
        flb_sds_destroy(ctx->federation_token);
    }
    ctx->federation_token = new_token;
    new_token = NULL;
    ctx->federation_token_expiry = flb_gcp_federation_token_expiry(
                                       now,
                                       sts_c->resp.payload,
                                       sts_c->resp.payload_size,
                                       iam_c ? iam_c->resp.payload : NULL,
                                       iam_c ? iam_c->resp.payload_size : 0);
    ret = 0;

    gcp_log_info(ctx, "retrieved Google access token via Workload "
                 "Identity Federation");

cleanup:
    flb_sds_destroy(subject_token);
    flb_sds_destroy(audience_esc);
    flb_sds_destroy(token_type_esc);
    flb_sds_destroy(subject_token_esc);
    flb_sds_destroy(scope_esc);
    flb_sds_destroy(sts_scope_esc);
    flb_sds_destroy(sts_body);
    flb_sds_destroy(federated_token);
    flb_sds_destroy(iam_url);
    flb_sds_destroy(iam_body);
    flb_sds_destroy(auth_header);
    flb_sds_destroy(new_token);
    if (sts_c) {
        flb_http_client_destroy(sts_c);
    }
    if (iam_c) {
        flb_http_client_destroy(iam_c);
    }
    if (sts_conn) {
        flb_upstream_conn_release(sts_conn);
    }
    if (iam_conn) {
        flb_upstream_conn_release(iam_conn);
    }
    return ret;
}

flb_sds_t flb_gcp_auth_get_header(struct flb_gcp_auth *ctx)
{
    int ret = 0;
    flb_sds_t output = NULL;
    flb_sds_t tmp;

    if (!ctx) {
        return NULL;
    }

    if (pthread_mutex_lock(&ctx->token_mutex)) {
        return NULL;
    }

    if (ctx->has_identity_federation) {
        if (!ctx->federation_token ||
            ctx->federation_token_expiry <= time(NULL)) {
            ret = gcp_exchange_identity_federation_token(ctx);
        }

        if (ret == 0 && ctx->federation_token) {
            output = flb_sds_create_size(flb_sds_len(ctx->federation_token) +
                                         sizeof("Bearer "));
            if (output) {
                tmp = flb_sds_printf(&output, "Bearer %s", ctx->federation_token);
                if (!tmp) {
                    flb_sds_destroy(output);
                    output = NULL;
                }
                else {
                    output = tmp;
                }
            }
        }
    }
    else {
        if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
            ret = gcp_get_oauth2_token(ctx);
        }

        if (ret == 0) {
            output = flb_sds_create(ctx->o->token_type);
            if (output) {
                tmp = flb_sds_printf(&output, " %s", ctx->o->access_token);
                if (!tmp) {
                    flb_sds_destroy(output);
                    output = NULL;
                }
                else {
                    output = tmp;
                }
            }
        }
    }

    pthread_mutex_unlock(&ctx->token_mutex);
    return output;
}

void flb_gcp_auth_invalidate_token(struct flb_gcp_auth *ctx)
{
    if (!ctx) {
        return;
    }

    if (pthread_mutex_lock(&ctx->token_mutex)) {
        return;
    }

    if (ctx->has_identity_federation) {
        ctx->federation_token_expiry = 0;
        if (ctx->federation_token) {
            flb_sds_destroy(ctx->federation_token);
            ctx->federation_token = NULL;
        }
    }
    else if (ctx->o) {
        flb_oauth2_invalidate_token(ctx->o);
    }

    pthread_mutex_unlock(&ctx->token_mutex);
}

int flb_gcp_auth_uses_metadata_server(struct flb_gcp_auth *ctx)
{
    if (ctx && ctx->metadata_server_auth == FLB_TRUE) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

int flb_gcp_auth_uses_identity_federation(struct flb_gcp_auth *ctx)
{
    if (ctx && ctx->has_identity_federation == FLB_TRUE) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/* http:// endpoints (tests, emulators) do not use TLS */
static int gcp_url_is_plain_http(const char *url)
{
    return strncasecmp(url, "http://", 7) == 0;
}

static int gcp_init_identity_federation(struct flb_gcp_auth *ctx,
                                        const struct flb_gcp_auth_config *cfg)
{
    int io_flags = FLB_IO_TLS;
    int sts_flags;
    int iam_flags;
    const char *sts_url = cfg->sts_url ? cfg->sts_url : FLB_GCP_GOOGLE_STS_URL;
    const char *iam_url = cfg->iam_url ? cfg->iam_url : FLB_GCP_GOOGLE_IAM_URL;
    struct flb_tls *sts_tls = NULL;
    struct flb_tls *iam_tls = NULL;

    if (cfg->ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }
    sts_flags = io_flags;
    iam_flags = io_flags;
    if (gcp_url_is_plain_http(sts_url)) {
        sts_flags &= ~FLB_IO_TLS;
        sts_flags |= FLB_IO_TCP;
    }
    if (gcp_url_is_plain_http(iam_url)) {
        iam_flags &= ~FLB_IO_TLS;
        iam_flags |= FLB_IO_TCP;
    }

    if (!cfg->project_number) {
        gcp_log_error(ctx, "'project_number' is required when "
                      "'enable_identity_federation' is true");
        return -1;
    }
    if (!cfg->pool_id) {
        gcp_log_error(ctx, "'pool_id' is required when "
                      "'enable_identity_federation' is true");
        return -1;
    }
    if (!cfg->provider_id) {
        gcp_log_error(ctx, "'provider_id' is required when "
                      "'enable_identity_federation' is true");
        return -1;
    }
    if (!cfg->identity_token_file) {
        gcp_log_error(ctx, "'identity_token_file' is required when "
                      "'enable_identity_federation' is true");
        return -1;
    }

    ctx->project_number = gcp_sds_dup(cfg->project_number);
    ctx->pool_id = gcp_sds_dup(cfg->pool_id);
    ctx->provider_id = gcp_sds_dup(cfg->provider_id);
    ctx->identity_token_file = gcp_sds_dup(cfg->identity_token_file);
    ctx->google_service_account = gcp_sds_dup(cfg->google_service_account);
    ctx->subject_token_type = gcp_sds_dup(cfg->subject_token_type ?
                                          cfg->subject_token_type :
                                          FLB_GCP_STS_SUBJECT_TOKEN_TYPE);
    if (!ctx->project_number || !ctx->pool_id || !ctx->provider_id ||
        !ctx->identity_token_file || !ctx->subject_token_type ||
        (cfg->google_service_account && !ctx->google_service_account)) {
        return -1;
    }

    /* Build the STS audience (workload identity pool provider resource name) */
    ctx->sts_audience = flb_sds_create_size(256);
    if (!ctx->sts_audience) {
        return -1;
    }
    if (!flb_sds_printf(&ctx->sts_audience, FLB_GCP_TARGET_RESOURCE_TEMPLATE,
                        ctx->project_number, ctx->pool_id, ctx->provider_id)) {
        return -1;
    }

    /* Google STS upstream (token exchange) */
    if (sts_flags & FLB_IO_TLS) {
        ctx->sts_tls = flb_tls_create(FLB_TLS_CLIENT_MODE, cfg->tls_verify,
                                      cfg->tls_debug, cfg->tls_vhost,
                                      cfg->tls_ca_path, cfg->tls_ca_file,
                                      cfg->tls_crt_file, cfg->tls_key_file,
                                      cfg->tls_key_passwd);
        if (!ctx->sts_tls) {
            gcp_log_error(ctx, "failed to create Google STS TLS context");
            return -1;
        }
        flb_tls_set_verify_hostname(ctx->sts_tls, cfg->tls_verify_hostname);
        sts_tls = ctx->sts_tls;
    }

    ctx->sts_u = flb_upstream_create_url(ctx->config, sts_url, sts_flags, sts_tls);
    if (!ctx->sts_u) {
        gcp_log_error(ctx, "failed to create Google STS upstream");
        return -1;
    }
    flb_stream_disable_async_mode(&ctx->sts_u->base);

    /* Google IAM Credentials upstream (only needed for impersonation) */
    if (ctx->google_service_account) {
        if (iam_flags & FLB_IO_TLS) {
            ctx->iam_tls = flb_tls_create(FLB_TLS_CLIENT_MODE, cfg->tls_verify,
                                          cfg->tls_debug, cfg->tls_vhost,
                                          cfg->tls_ca_path, cfg->tls_ca_file,
                                          cfg->tls_crt_file, cfg->tls_key_file,
                                          cfg->tls_key_passwd);
            if (!ctx->iam_tls) {
                gcp_log_error(ctx, "failed to create Google IAM TLS context");
                return -1;
            }
            flb_tls_set_verify_hostname(ctx->iam_tls, cfg->tls_verify_hostname);
            iam_tls = ctx->iam_tls;
        }

        ctx->iam_u = flb_upstream_create_url(ctx->config, iam_url, iam_flags,
                                             iam_tls);
        if (!ctx->iam_u) {
            gcp_log_error(ctx, "failed to create Google IAM upstream");
            return -1;
        }
        flb_stream_disable_async_mode(&ctx->iam_u->base);
    }

    gcp_log_info(ctx, "Workload Identity Federation enabled "
                 "(audience=%s, impersonation=%s)",
                 ctx->sts_audience,
                 ctx->google_service_account ? ctx->google_service_account : "none");
    return 0;
}

static int gcp_init_oauth2(struct flb_gcp_auth *ctx,
                           const struct flb_gcp_auth_config *cfg)
{
    struct flb_oauth2_config oauth2_cfg;

    memset(&oauth2_cfg, 0, sizeof(oauth2_cfg));
    oauth2_cfg.enabled = FLB_TRUE;
    oauth2_cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    oauth2_cfg.refresh_skew = FLB_OAUTH2_DEFAULT_SKEW_SECS;
    oauth2_cfg.token_url = flb_sds_create(FLB_GCP_AUTH_URL);
    if (!oauth2_cfg.token_url) {
        return -1;
    }

    ctx->o = flb_oauth2_create_from_settings(ctx->config,
                                             cfg->tls_verify_hostname,
                                             &oauth2_cfg);
    flb_oauth2_config_destroy(&oauth2_cfg);

    return ctx->o ? 0 : -1;
}

static int gcp_resolve_service_account(struct flb_gcp_auth *ctx,
                                       const struct flb_gcp_auth_config *cfg)
{
    const char *tmp;
    const char *legacy_credentials;
    const char *server;

    tmp = getenv("GOOGLE_APPLICATION_CREDENTIALS");
    legacy_credentials = getenv("GOOGLE_SERVICE_CREDENTIALS");
    if (!cfg->credentials_file && tmp && legacy_credentials) {
        gcp_log_warn(ctx, "GOOGLE_APPLICATION_CREDENTIALS and "
                     "GOOGLE_SERVICE_CREDENTIALS are both set; using "
                     "GOOGLE_APPLICATION_CREDENTIALS");
    }
    if (!cfg->credentials_file && !tmp) {
        tmp = legacy_credentials;
    }

    if (cfg->credentials_file) {
        ctx->credentials_file = flb_sds_create(cfg->credentials_file);
        if (!ctx->credentials_file) {
            return -1;
        }
    }
    else if (tmp) {
        ctx->credentials_file = flb_sds_create(tmp);
        if (!ctx->credentials_file) {
            return -1;
        }
    }

    if (ctx->credentials_file) {
        ctx->credentials = flb_calloc(1, sizeof(struct flb_gcp_credentials));
        if (!ctx->credentials) {
            flb_errno();
            return -1;
        }

        if (flb_gcp_credentials_read(ctx->credentials_file,
                                     ctx->credentials) == -1) {
            gcp_log_error(ctx, "failed to load the service account credentials");
            return -1;
        }
    }
    else {
        ctx->metadata_server_auth = FLB_TRUE;
        gcp_log_info(ctx, "using GCE/GKE metadata server authentication");
    }

    if (gcp_init_oauth2(ctx, cfg) != 0) {
        return -1;
    }

    if (ctx->metadata_server_auth == FLB_TRUE) {
        server = cfg->metadata_server ? cfg->metadata_server :
                 FLB_GCP_METADATA_SERVER;
        ctx->metadata_server = flb_sds_create(server);
        if (!ctx->metadata_server) {
            return -1;
        }

        ctx->metadata_u = flb_upstream_create_url(ctx->config,
                                                  ctx->metadata_server,
                                                  FLB_IO_TCP, NULL);
        if (!ctx->metadata_u) {
            gcp_log_error(ctx, "metadata upstream creation failed");
            return -1;
        }
        flb_stream_disable_async_mode(&ctx->metadata_u->base);
    }

    return 0;
}

void flb_gcp_auth_destroy(struct flb_gcp_auth *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->metadata_u) {
        flb_upstream_destroy(ctx->metadata_u);
    }

    if (ctx->o) {
        flb_oauth2_destroy(ctx->o);
    }

    if (ctx->sts_u) {
        flb_upstream_destroy(ctx->sts_u);
    }

    if (ctx->iam_u) {
        flb_upstream_destroy(ctx->iam_u);
    }

    if (ctx->sts_tls) {
        flb_tls_destroy(ctx->sts_tls);
    }

    if (ctx->iam_tls) {
        flb_tls_destroy(ctx->iam_tls);
    }

    flb_gcp_credentials_destroy(ctx->credentials);

    flb_sds_destroy(ctx->log_prefix);
    flb_sds_destroy(ctx->scope);
    flb_sds_destroy(ctx->credentials_file);
    flb_sds_destroy(ctx->metadata_server);
    flb_sds_destroy(ctx->project_number);
    flb_sds_destroy(ctx->pool_id);
    flb_sds_destroy(ctx->provider_id);
    flb_sds_destroy(ctx->identity_token_file);
    flb_sds_destroy(ctx->google_service_account);
    flb_sds_destroy(ctx->subject_token_type);
    flb_sds_destroy(ctx->sts_audience);
    flb_sds_destroy(ctx->federation_token);

    if (ctx->token_mutex_initialized == FLB_TRUE) {
        pthread_mutex_destroy(&ctx->token_mutex);
    }

    flb_free(ctx);
}

struct flb_gcp_auth *flb_gcp_auth_create(const struct flb_gcp_auth_config *cfg)
{
    struct flb_gcp_auth *ctx;
    flb_sds_t tmp;

    if (!cfg || !cfg->config) {
        flb_error("[gcp_auth] configuration is not set");
        return NULL;
    }

    if (!cfg->scope || cfg->scope[0] == '\0') {
        flb_error("[gcp_auth] scope is required");
        return NULL;
    }

    ctx = flb_calloc(1, sizeof(struct flb_gcp_auth));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->config = cfg->config;
    ctx->metadata_fetch = cfg->metadata_fetch;
    ctx->metadata_fetch_data = cfg->metadata_fetch_data;

    if (cfg->log_name && cfg->log_name[0] != '\0') {
        ctx->log_prefix = flb_sds_create_size(16 + strlen(cfg->log_name));
        if (ctx->log_prefix) {
            tmp = flb_sds_printf(&ctx->log_prefix, "[gcp_auth:%s]", cfg->log_name);
            if (!tmp) {
                /* printf failed: sds is still owned by ctx and freed below */
                goto error;
            }
        }
    }
    else {
        ctx->log_prefix = flb_sds_create("[gcp_auth]");
    }
    if (!ctx->log_prefix) {
        goto error;
    }

    ctx->scope = flb_sds_create(cfg->scope);
    if (!ctx->scope) {
        goto error;
    }

    if (pthread_mutex_init(&ctx->token_mutex, NULL) == 0) {
        ctx->token_mutex_initialized = FLB_TRUE;
    }
    else {
        goto error;
    }

    if (cfg->identity_federation == FLB_TRUE) {
        if (cfg->credentials_file) {
            gcp_log_error(ctx, "'google_service_credentials' and "
                          "'enable_identity_federation' are mutually exclusive");
            goto error;
        }

        ctx->has_identity_federation = FLB_TRUE;
        if (gcp_init_identity_federation(ctx, cfg) == -1) {
            goto error;
        }
    }
    else if (gcp_resolve_service_account(ctx, cfg) == -1) {
        goto error;
    }

    return ctx;

error:
    flb_gcp_auth_destroy(ctx);
    return NULL;
}
