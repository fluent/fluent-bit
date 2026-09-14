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

/*
 * Workload Identity Federation support for the Stackdriver output plugin.
 *
 * Flow:
 *   1. Read the subject token from credential_source. Two variants are
 *      supported: a local file (credential_source.file) or an HTTPS GET
 *      against credential_source.url with optional headers. Both honor
 *      credential_source.format (text or json).
 *   2. Exchange it at the STS token endpoint for a federated access token.
 *   3. If service_account_impersonation_url is set, call the IAM Credentials
 *      generateAccessToken endpoint (optionally through a delegation chain)
 *      to obtain the final service-account access token.
 *   4. Store the resulting access token in ctx->o so that the existing
 *      get_google_token() machinery uses it transparently.
 *
 * Security note: token_url, service_account_impersonation_url and
 * credential_source.url are trusted as supplied in the credentials file.
 * Operators handling untrusted credential files should isolate fluent-bit
 * at the network layer.
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_strptime.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/tls/flb_tls.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <yyjson.h>

#include "stackdriver.h"
#include "stackdriver_external_account.h"

/* Maximum size of any HTTP response body we care about (STS, impersonation) */
#define WIF_HTTP_BUFFER_SIZE (64 * 1024)

/* Maximum size we will accept for a subject token file */
#define WIF_SUBJECT_TOKEN_MAX_SIZE (1 * 1024 * 1024)

/* Forward declaration: definition appears below read_subject_token_from_url. */
static struct flb_upstream *wif_get_upstream(struct flb_stackdriver *ctx,
                                             struct flb_upstream **slot,
                                             const char *url);

int stackdriver_external_account_is_configured(struct flb_stackdriver *ctx)
{
    if (!ctx || !ctx->creds || !ctx->creds->type) {
        return FLB_FALSE;
    }

    if (strcmp(ctx->creds->type,
               FLB_STD_CREDENTIAL_TYPE_EXTERNAL_ACCOUNT) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/* Strip ASCII whitespace from both ends of an sds buffer (in-place) */
static void wif_sds_trim_ws(flb_sds_t s)
{
    int i;
    int len;
    int start = 0;
    int end;

    if (!s) {
        return;
    }

    len = flb_sds_len(s);
    end = len;

    while (start < len &&
           (s[start] == ' '  || s[start] == '\t' ||
            s[start] == '\r' || s[start] == '\n')) {
        start++;
    }

    while (end > start &&
           (s[end - 1] == ' '  || s[end - 1] == '\t' ||
            s[end - 1] == '\r' || s[end - 1] == '\n')) {
        end--;
    }

    if (start == 0 && end == len) {
        return;
    }

    if (start > 0) {
        for (i = 0; i < (end - start); i++) {
            s[i] = s[start + i];
        }
    }

    s[end - start] = '\0';
    flb_sds_len_set(s, end - start);
}

/*
 * Apply the credential_source.format rules to a freshly-fetched subject
 * token buffer (whether it came from a file or an HTTP GET). Takes
 * ownership of `raw` and returns a new flb_sds_t the caller must free.
 *
 * format == nil or "text"  -> return raw, whitespace-trimmed
 * format == "json"          -> parse as JSON, extract subject_token_field_name
 */
static flb_sds_t extract_subject_token(struct flb_stackdriver *ctx,
                                       const char *source_label,
                                       flb_sds_t raw)
{
    flb_sds_t token = NULL;
    yyjson_doc *doc = NULL;
    yyjson_val *root;
    yyjson_val *v;
    const char *format_type;
    const char *field_name;

    if (!raw) {
        return NULL;
    }

    wif_sds_trim_ws(raw);

    format_type = ctx->creds->cred_source_format_type;
    if (!format_type ||
        flb_sds_len(ctx->creds->cred_source_format_type) == 0 ||
        strcasecmp(format_type, "text") == 0) {
        return raw;
    }

    if (strcasecmp(format_type, "json") != 0) {
        flb_plg_error(ctx->ins, "external_account: unsupported "
                      "credential_source.format.type '%s' (expected "
                      "'text' or 'json')", format_type);
        flb_sds_destroy(raw);
        return NULL;
    }

    field_name = ctx->creds->cred_source_format_subject_field;
    if (!field_name ||
        flb_sds_len(ctx->creds->cred_source_format_subject_field) == 0) {
        flb_plg_error(ctx->ins, "external_account: "
                      "credential_source.format.subject_token_field_name "
                      "is required when format.type is 'json'");
        flb_sds_destroy(raw);
        return NULL;
    }

    doc = yyjson_read(raw, flb_sds_len(raw), 0);
    if (!doc) {
        flb_plg_error(ctx->ins, "external_account: subject token from %s "
                      "is not valid JSON", source_label);
        flb_sds_destroy(raw);
        return NULL;
    }
    root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        flb_plg_error(ctx->ins, "external_account: subject token from %s "
                      "is not a JSON object", source_label);
        yyjson_doc_free(doc);
        flb_sds_destroy(raw);
        return NULL;
    }

    v = yyjson_obj_get(root, field_name);
    if (!v) {
        flb_plg_error(ctx->ins, "external_account: subject token field "
                      "'%s' not found in %s", field_name, source_label);
    }
    else if (!yyjson_is_str(v)) {
        flb_plg_error(ctx->ins, "external_account: '%s' field in subject "
                      "token from %s is not a string",
                      field_name, source_label);
    }
    else {
        token = flb_sds_create(yyjson_get_str(v));
    }

    yyjson_doc_free(doc);
    flb_sds_destroy(raw);
    return token;
}

static flb_sds_t read_subject_token_from_file(struct flb_stackdriver *ctx)
{
    int ret;
    size_t buf_len;
    char *buf = NULL;
    flb_sds_t raw = NULL;
    struct stat st;
    const char *path;

    path = ctx->creds->cred_source_file;
    if (!path || flb_sds_len(ctx->creds->cred_source_file) == 0) {
        flb_plg_error(ctx->ins, "external_account: credential_source.file "
                      "is required");
        return NULL;
    }

    if (stat(path, &st) == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "external_account: cannot stat subject "
                      "token file: %s", path);
        return NULL;
    }
    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "external_account: subject token path is "
                      "not a regular file: %s", path);
        return NULL;
    }
    if (st.st_size <= 0 || st.st_size > WIF_SUBJECT_TOKEN_MAX_SIZE) {
        flb_plg_error(ctx->ins, "external_account: subject token file size "
                      "is invalid (%lld bytes): %s",
                      (long long) st.st_size, path);
        return NULL;
    }

    ret = flb_utils_read_file((char *) path, &buf, &buf_len);
    if (ret != 0 || !buf || buf_len == 0) {
        flb_plg_error(ctx->ins, "external_account: failed to read subject "
                      "token file: %s", path);
        if (buf) {
            flb_free(buf);
        }
        return NULL;
    }

    raw = flb_sds_create_len(buf, buf_len);
    flb_free(buf);
    if (!raw) {
        flb_errno();
        return NULL;
    }

    return extract_subject_token(ctx, path, raw);
}

/*
 * Fetch the subject token from credential_source.url. Mirrors the file
 * provider but with an HTTPS GET against the configured URL, optionally
 * carrying caller-defined headers.
 */
static flb_sds_t read_subject_token_from_url(struct flb_stackdriver *ctx)
{
    int ret;
    int port_n;
    int h;
    size_t b_sent = 0;
    const char *url;
    const char *path;
    flb_sds_t hk;
    flb_sds_t hv;
    char *prot = NULL;
    char *url_host = NULL;
    char *url_port = NULL;
    char *url_uri = NULL;
    flb_sds_t raw = NULL;
    struct flb_upstream *u;
    struct flb_connection *conn = NULL;
    struct flb_http_client *c = NULL;

    url = ctx->creds->cred_source_url;
    if (!url || flb_sds_len(ctx->creds->cred_source_url) == 0) {
        flb_plg_error(ctx->ins, "external_account: credential_source.url "
                      "is required");
        return NULL;
    }

    u = wif_get_upstream(ctx, &ctx->wif_subject_url_u, url);
    if (!u) {
        return NULL;
    }

    if (flb_utils_url_split(url, &prot, &url_host, &url_port, &url_uri)
        != 0) {
        flb_plg_error(ctx->ins, "external_account: failed to parse "
                      "credential_source.url: %s", url);
        return NULL;
    }
    path = (url_uri && url_uri[0]) ? url_uri : "/";
    /*
     * Default port: 443 for https, 80 for http. If a port was specified
     * in the URL, that wins.
     */
    if (url_port) {
        port_n = atoi(url_port);
    }
    else if (prot && strcasecmp(prot, "http") == 0) {
        port_n = 80;
    }
    else {
        port_n = 443;
    }

    conn = flb_upstream_conn_get(u);
    if (!conn) {
        flb_plg_error(ctx->ins, "external_account: failed to connect to "
                      "credential_source.url: %s", url);
        goto cleanup;
    }

    c = flb_http_client(conn, FLB_HTTP_GET, path,
                        NULL, 0,
                        url_host, port_n, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "external_account: failed to create HTTP "
                      "client for credential_source.url");
        goto cleanup;
    }

    flb_http_buffer_size(c, WIF_HTTP_BUFFER_SIZE);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    for (h = 0; h < ctx->creds->cred_source_headers_count; h++) {
        hk = ctx->creds->cred_source_headers_keys[h];
        hv = ctx->creds->cred_source_headers_vals[h];
        if (hk && hv) {
            flb_http_add_header(c,
                                hk, flb_sds_len(hk),
                                hv, flb_sds_len(hv));
        }
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "external_account: credential_source.url "
                      "HTTP request failed (ret=%d)", ret);
        goto cleanup;
    }

    if (c->resp.status < 200 || c->resp.status >= 300) {
        flb_plg_error(ctx->ins,
                      "external_account: credential_source.url returned "
                      "HTTP %d: %.*s",
                      c->resp.status,
                      (int) c->resp.payload_size,
                      c->resp.payload ? c->resp.payload : "");
        goto cleanup;
    }
    if (!c->resp.payload || c->resp.payload_size == 0) {
        flb_plg_error(ctx->ins, "external_account: credential_source.url "
                      "returned an empty response");
        goto cleanup;
    }

    raw = flb_sds_create_len(c->resp.payload, c->resp.payload_size);

cleanup:
    if (c) {
        flb_http_client_destroy(c);
    }
    if (conn) {
        flb_upstream_conn_release(conn);
    }
    flb_free(prot);
    flb_free(url_host);
    flb_free(url_port);
    flb_free(url_uri);

    if (!raw) {
        return NULL;
    }
    return extract_subject_token(ctx, url, raw);
}

/*
 * Strict x-www-form-urlencoded encoder. flb_uri_encode does not escape
 * '&', '=', '?' or '/', which are field separators in form bodies; using
 * it here would silently corrupt STS requests if a value (e.g. workforce
 * options JSON) contained any of them. Instead we percent-encode every
 * byte that is not in the RFC 3986 unreserved set.
 */
static int wif_form_encode_value(flb_sds_t *buf, const char *src, size_t len)
{
    size_t i;
    char hex[4];
    unsigned char c;

    for (i = 0; i < len; i++) {
        c = (unsigned char) src[i];
        if ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            if (flb_sds_cat_safe(buf, (const char *) &c, 1) != 0) {
                return -1;
            }
        }
        else {
            snprintf(hex, sizeof(hex), "%%%02X", c);
            if (flb_sds_cat_safe(buf, hex, 3) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

/* Append a key/value pair as URL-encoded form data to buf */
static int wif_form_append(flb_sds_t *buf, const char *key, const char *value)
{
    int ret;
    size_t value_len;

    if (!value) {
        return 0;
    }
    value_len = strlen(value);
    if (value_len == 0) {
        return 0;
    }

    if (flb_sds_len(*buf) > 0) {
        ret = flb_sds_cat_safe(buf, "&", 1);
        if (ret != 0) {
            return -1;
        }
    }

    ret = flb_sds_cat_safe(buf, key, strlen(key));
    if (ret != 0) {
        return -1;
    }

    ret = flb_sds_cat_safe(buf, "=", 1);
    if (ret != 0) {
        return -1;
    }

    return wif_form_encode_value(buf, value, value_len);
}

/*
 * Lazily create an upstream for the given URL. STS and IAM are always
 * https://, but credential_source.url legitimately allows plain http://
 * (sidecar token providers on localhost). Pass FLB_IO_TLS only when the
 * URL is https://; flb_upstream_create_url() also force-enables TLS for
 * https:// regardless, which keeps STS/IAM safe.
 */
static struct flb_upstream *wif_get_upstream(struct flb_stackdriver *ctx,
                                             struct flb_upstream **slot,
                                             const char *url)
{
    int io_flags;
    struct flb_upstream *u;

    if (*slot) {
        return *slot;
    }

    io_flags = (strncasecmp(url, "https://", 8) == 0) ? FLB_IO_TLS : FLB_IO_TCP;
    u = flb_upstream_create_url(ctx->config, url, io_flags, ctx->ins->tls);
    if (!u) {
        flb_plg_error(ctx->ins, "external_account: failed to create "
                      "upstream for %s", url);
        return NULL;
    }

    flb_stream_disable_async_mode(&u->base);
    *slot = u;
    return u;
}

/*
 * Performs the STS token exchange. On success, fills *out_access_token /
 * *out_token_type / *out_expires_in (caller owns the sds strings) and
 * returns 0.
 */
static int wif_sts_exchange(struct flb_stackdriver *ctx,
                            const char *subject_token,
                            const char *scope,
                            flb_sds_t *out_access_token,
                            flb_sds_t *out_token_type,
                            uint64_t   *out_expires_in)
{
    int ret;
    int rc = -1;
    int port_n;
    size_t b_sent = 0;
    const char *token_url;
    const char *path;
    const char *universe;
    const char *provider;
    char *prot = NULL;
    char *url_host = NULL;
    char *url_port = NULL;
    char *url_uri = NULL;
    flb_sds_t default_token_url = NULL;
    flb_sds_t api_client_header = NULL;
    flb_sds_t body = NULL;
    flb_sds_t options_json = NULL;
    struct flb_upstream *u;
    struct flb_connection *conn = NULL;
    struct flb_http_client *c = NULL;
    struct flb_oauth2 tmp_oauth = {0};

    *out_access_token = NULL;
    *out_token_type = NULL;
    *out_expires_in = 0;

    token_url = ctx->creds->token_url;
    if (!ctx->creds->token_url || flb_sds_len(ctx->creds->token_url) == 0) {
        /*
         * No explicit token_url in the credentials file. Fall back to the
         * default STS endpoint, substituting universe_domain when set so
         * non-googleapis.com clouds (sovereign / GDU) route correctly.
         */
        universe = ctx->creds->universe_domain;
        if (universe && flb_sds_len(ctx->creds->universe_domain) > 0 &&
            strcmp(universe, "googleapis.com") != 0) {
            default_token_url = flb_sds_create_size(64);
            if (!default_token_url) {
                flb_errno();
                return -1;
            }
            if (!flb_sds_printf(&default_token_url,
                                "https://sts.%s/v1/token", universe)) {
                flb_sds_destroy(default_token_url);
                return -1;
            }
            token_url = default_token_url;
        }
        else {
            token_url = FLB_STD_DEFAULT_STS_TOKEN_URL;
        }
    }

    u = wif_get_upstream(ctx, &ctx->wif_sts_u, token_url);
    if (!u) {
        return -1;
    }

    body = flb_sds_create_size(1024);
    if (!body) {
        flb_errno();
        return -1;
    }

    if (wif_form_append(&body, "audience", ctx->creds->audience) ||
        wif_form_append(&body, "grant_type",
                        FLB_STD_TOKEN_EXCHANGE_GRANT_TYPE) ||
        wif_form_append(&body, "requested_token_type",
                        FLB_STD_TOKEN_TYPE_ACCESS_TOKEN) ||
        wif_form_append(&body, "subject_token_type",
                        ctx->creds->subject_token_type) ||
        wif_form_append(&body, "subject_token", subject_token) ||
        wif_form_append(&body, "scope", scope)) {
        flb_plg_error(ctx->ins, "external_account: failed to build STS "
                      "request body");
        goto cleanup;
    }

    /*
     * For workforce pools without a client_id, inject
     * options={"userProject":"<project>"} into the form body. Build
     * via yyjson_mut so a stray quote or backslash in the project
     * value cannot produce malformed JSON.
     */
    if (ctx->creds->workforce_pool_user_project &&
        flb_sds_len(ctx->creds->workforce_pool_user_project) > 0 &&
        (!ctx->creds->client_id ||
         flb_sds_len(ctx->creds->client_id) == 0)) {
        yyjson_mut_doc *opts_doc;
        yyjson_mut_val *opts_root;
        char *opts_str;

        opts_doc = yyjson_mut_doc_new(NULL);
        if (!opts_doc) {
            flb_errno();
            goto cleanup;
        }
        opts_root = yyjson_mut_obj(opts_doc);
        yyjson_mut_obj_add_str(opts_doc, opts_root, "userProject",
                               ctx->creds->workforce_pool_user_project);
        yyjson_mut_doc_set_root(opts_doc, opts_root);
        opts_str = yyjson_mut_write(opts_doc, 0, NULL);
        if (!opts_str) {
            yyjson_mut_doc_free(opts_doc);
            goto cleanup;
        }
        options_json = flb_sds_create(opts_str);
        free(opts_str);
        yyjson_mut_doc_free(opts_doc);
        if (!options_json) {
            goto cleanup;
        }
        if (wif_form_append(&body, "options", options_json) != 0) {
            goto cleanup;
        }
    }

    conn = flb_upstream_conn_get(u);
    if (!conn) {
        flb_plg_error(ctx->ins, "external_account: failed to connect to "
                      "STS endpoint %s", token_url);
        goto cleanup;
    }

    /*
     * flb_http_client() needs the request-line URI (e.g. "/v1/token") and
     * benefits from an explicit host so the Host header is correct. The
     * upstream already parsed token_url for connection purposes, but we
     * have to re-parse here to get the path component for the request line.
     * Without it the request line becomes "POST  HTTP/1.1" and Google's
     * frontend rejects it with HTTP 411.
     */
    if (flb_utils_url_split(token_url, &prot, &url_host, &url_port,
                            &url_uri) != 0) {
        flb_plg_error(ctx->ins, "external_account: failed to parse "
                      "token_url: %s", token_url);
        goto cleanup;
    }
    path = (url_uri && url_uri[0]) ? url_uri : "/";
    port_n = url_port ? atoi(url_port) : 443;

    c = flb_http_client(conn, FLB_HTTP_POST, path,
                        body, flb_sds_len(body),
                        url_host, port_n, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "external_account: failed to create HTTP "
                      "client for STS request");
        goto cleanup;
    }

    flb_http_buffer_size(c, WIF_HTTP_BUFFER_SIZE);
    flb_http_add_header(c,
                        "Content-Type", 12,
                        "application/x-www-form-urlencoded", 33);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    /*
     * x-goog-api-client lets Google identify and attribute traffic from
     * BYOID/external_account clients. Mirrors the Cloud SDK telemetry
     * format: <client>/<version> google-byoid-sdk source/<provider>
     * sa-impersonation/<bool> config-lifetime/<bool>.
     */
    api_client_header = flb_sds_create_size(160);
    if (api_client_header) {
        provider = "file";
        if (ctx->creds->cred_source_url &&
            flb_sds_len(ctx->creds->cred_source_url) > 0) {
            provider = "url";
        }
        flb_sds_printf(&api_client_header,
                       "fluent-bit/%s google-byoid-sdk source/%s "
                       "sa-impersonation/%s config-lifetime/%s",
                       FLB_VERSION_STR, provider,
                       (ctx->creds->service_account_impersonation_url &&
                        flb_sds_len(ctx->creds->service_account_impersonation_url) > 0)
                            ? "true" : "false",
                       (ctx->creds->sa_impersonation_lifetime_seconds > 0)
                            ? "true" : "false");
        flb_http_add_header(c, "x-goog-api-client", 17,
                            api_client_header,
                            flb_sds_len(api_client_header));
    }

    /*
     * If client_id and client_secret are present, authenticate the STS
     * call with HTTP Basic auth.
     */
    if (ctx->creds->client_id &&
        flb_sds_len(ctx->creds->client_id) > 0 &&
        ctx->creds->client_secret &&
        flb_sds_len(ctx->creds->client_secret) > 0) {
        ret = flb_http_basic_auth(c,
                                  ctx->creds->client_id,
                                  ctx->creds->client_secret);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "external_account: failed to set "
                          "STS basic auth header");
            goto cleanup;
        }
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "external_account: STS HTTP request "
                      "failed (ret=%d)", ret);
        goto cleanup;
    }

    if (c->resp.status != 200) {
        flb_plg_error(ctx->ins,
                      "external_account: STS exchange returned HTTP %d: %.*s",
                      c->resp.status,
                      (int) c->resp.payload_size,
                      c->resp.payload ? c->resp.payload : "");
        goto cleanup;
    }

    /*
     * Reuse the existing oauth2 JSON parser to extract access_token,
     * token_type and expires_in from the STS response.
     */
    ret = flb_oauth2_parse_json_response(c->resp.payload,
                                         c->resp.payload_size,
                                         &tmp_oauth);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "external_account: failed to parse STS "
                      "response");
        goto cleanup;
    }

    /*
     * RFC 8693 leaves expires_in == 0 undefined. expires_in is uint64_t,
     * so this guard catches missing or zero values; either would cache a
     * token that is treated as immediately expired and would trigger a
     * hot refresh loop.
     */
    if (tmp_oauth.expires_in <= 0) {
        flb_plg_error(ctx->ins, "external_account: STS returned invalid "
                      "expires_in=%" PRIu64, tmp_oauth.expires_in);
        goto cleanup;
    }

    *out_access_token = tmp_oauth.access_token;
    *out_token_type = tmp_oauth.token_type;
    *out_expires_in = tmp_oauth.expires_in;
    tmp_oauth.access_token = NULL;
    tmp_oauth.token_type = NULL;
    rc = 0;

cleanup:
    if (c) {
        flb_http_client_destroy(c);
    }
    if (conn) {
        flb_upstream_conn_release(conn);
    }
    if (tmp_oauth.access_token) {
        flb_sds_destroy(tmp_oauth.access_token);
    }
    if (tmp_oauth.token_type) {
        flb_sds_destroy(tmp_oauth.token_type);
    }
    if (options_json) {
        flb_sds_destroy(options_json);
    }
    if (body) {
        flb_sds_destroy(body);
    }
    if (default_token_url) {
        flb_sds_destroy(default_token_url);
    }
    if (api_client_header) {
        flb_sds_destroy(api_client_header);
    }
    flb_free(prot);
    flb_free(url_host);
    flb_free(url_port);
    flb_free(url_uri);
    return rc;
}

/*
 * Parse the impersonation response shape:
 *   {"accessToken":"ya29...","expireTime":"2024-01-01T00:00:00Z"}
 */
static int wif_parse_impersonation_response(struct flb_stackdriver *ctx,
                                            const char *json_data,
                                            size_t json_size,
                                            flb_sds_t *out_access_token,
                                            time_t *out_expires_at)
{
    int val_len;
    char tm_buf[64];
    char *endp;
    const char *val;
    struct flb_tm tm = {0};
    yyjson_doc *doc = NULL;
    yyjson_val *root;
    yyjson_val *v;

    *out_access_token = NULL;
    *out_expires_at = 0;

    doc = yyjson_read(json_data, json_size, 0);
    if (!doc) {
        flb_plg_error(ctx->ins, "external_account: impersonation response "
                      "is not valid JSON");
        return -1;
    }
    root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        flb_plg_error(ctx->ins, "external_account: impersonation response "
                      "is not a JSON object");
        yyjson_doc_free(doc);
        return -1;
    }

    v = yyjson_obj_get(root, "accessToken");
    if (yyjson_is_str(v)) {
        *out_access_token = flb_sds_create(yyjson_get_str(v));
    }

    /*
     * IAM Credentials returns RFC3339 with a "Z" suffix:
     * 2026-01-02T03:04:05Z. flb_strptime does not understand "%Z" portably,
     * so we consume the timestamp prefix and rely on UTC.
     */
    v = yyjson_obj_get(root, "expireTime");
    if (yyjson_is_str(v)) {
        val = yyjson_get_str(v);
        val_len = (int) yyjson_get_len(v);
        if (val_len > 0 && val_len < (int) sizeof(tm_buf)) {
            memcpy(tm_buf, val, val_len);
            tm_buf[val_len] = '\0';
            endp = flb_strptime(tm_buf, "%Y-%m-%dT%H:%M:%S", &tm);
            if (!endp) {
                flb_plg_warn(ctx->ins, "external_account: cannot parse "
                             "impersonation expireTime '%s'", tm_buf);
            }
            else {
                *out_expires_at = timegm(&tm.tm);
            }
        }
    }

    yyjson_doc_free(doc);

    if (!*out_access_token) {
        flb_plg_error(ctx->ins, "external_account: impersonation response "
                      "missing accessToken");
        return -1;
    }
    if (*out_expires_at == 0) {
        flb_plg_warn(ctx->ins, "external_account: impersonation response "
                     "missing or unparseable expireTime; defaulting to "
                     "%d seconds",
                     FLB_STD_DEFAULT_IMPERSONATION_LIFETIME_SECONDS);
        *out_expires_at = time(NULL) +
            FLB_STD_DEFAULT_IMPERSONATION_LIFETIME_SECONDS;
    }

    return 0;
}

static int wif_impersonate(struct flb_stackdriver *ctx,
                           const char *federated_token,
                           const char *scope,
                           flb_sds_t *out_access_token,
                           time_t *out_expires_at)
{
    int ret;
    int rc = -1;
    int lifetime;
    int port_n;
    int d;
    size_t b_sent = 0;
    char lifetime_buf[32];
    const char *path;
    char *prot = NULL;
    char *url_host = NULL;
    char *url_port = NULL;
    char *url_uri = NULL;
    char *body_str = NULL;
    flb_sds_t body = NULL;
    flb_sds_t auth_header = NULL;
    struct flb_upstream *u;
    struct flb_connection *conn = NULL;
    struct flb_http_client *c = NULL;
    yyjson_mut_doc *body_doc = NULL;
    yyjson_mut_val *body_root;
    yyjson_mut_val *scope_arr;
    yyjson_mut_val *delegates_arr;

    *out_access_token = NULL;
    *out_expires_at = 0;

    u = wif_get_upstream(ctx, &ctx->wif_iam_u,
                         ctx->creds->service_account_impersonation_url);
    if (!u) {
        return -1;
    }

    lifetime = ctx->creds->sa_impersonation_lifetime_seconds;
    if (lifetime <= 0) {
        lifetime = FLB_STD_DEFAULT_IMPERSONATION_LIFETIME_SECONDS;
    }

    /*
     * Build the impersonation request body via yyjson_mut so that any
     * special characters in scope or delegate emails are properly
     * escaped. The IAM Credentials API expects:
     *   {"lifetime":"<N>s","scope":[...],"delegates":[...]}
     */
    body_doc = yyjson_mut_doc_new(NULL);
    if (!body_doc) {
        flb_errno();
        return -1;
    }
    body_root = yyjson_mut_obj(body_doc);

    snprintf(lifetime_buf, sizeof(lifetime_buf), "%ds", lifetime);
    yyjson_mut_obj_add_str(body_doc, body_root, "lifetime", lifetime_buf);

    scope_arr = yyjson_mut_arr(body_doc);
    yyjson_mut_arr_add_str(body_doc, scope_arr, scope);
    yyjson_mut_obj_add_val(body_doc, body_root, "scope", scope_arr);

    /*
     * Optional delegation chain. Each delegate must have
     * iam.serviceAccountTokenCreator on the next entry; the impersonation
     * URL's target service account ends the chain.
     */
    if (ctx->creds->sa_impersonation_delegates_count > 0) {
        delegates_arr = yyjson_mut_arr(body_doc);
        for (d = 0;
             d < ctx->creds->sa_impersonation_delegates_count;
             d++) {
            yyjson_mut_arr_add_str(body_doc, delegates_arr,
                ctx->creds->sa_impersonation_delegates[d]);
        }
        yyjson_mut_obj_add_val(body_doc, body_root, "delegates",
                               delegates_arr);
    }

    yyjson_mut_doc_set_root(body_doc, body_root);
    body_str = yyjson_mut_write(body_doc, 0, NULL);
    if (!body_str) {
        flb_plg_error(ctx->ins, "external_account: failed to serialise "
                      "impersonation body");
        goto cleanup;
    }
    body = flb_sds_create(body_str);
    if (!body) {
        goto cleanup;
    }

    auth_header = flb_sds_create_size(strlen(federated_token) + 16);
    if (!auth_header) {
        flb_errno();
        goto cleanup;
    }
    if (!flb_sds_printf(&auth_header, "Bearer %s", federated_token)) {
        goto cleanup;
    }

    conn = flb_upstream_conn_get(u);
    if (!conn) {
        flb_plg_error(ctx->ins, "external_account: failed to connect to "
                      "IAM Credentials endpoint");
        goto cleanup;
    }

    if (flb_utils_url_split(ctx->creds->service_account_impersonation_url,
                            &prot, &url_host, &url_port, &url_uri) != 0) {
        flb_plg_error(ctx->ins, "external_account: failed to parse "
                      "service_account_impersonation_url");
        goto cleanup;
    }
    path = (url_uri && url_uri[0]) ? url_uri : "/";
    port_n = url_port ? atoi(url_port) : 443;

    c = flb_http_client(conn, FLB_HTTP_POST, path,
                        body, flb_sds_len(body),
                        url_host, port_n, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "external_account: failed to create HTTP "
                      "client for impersonation request");
        goto cleanup;
    }

    flb_http_buffer_size(c, WIF_HTTP_BUFFER_SIZE);
    flb_http_add_header(c, "Content-Type", 12,
                        "application/json", 16);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Authorization", 13,
                        auth_header, flb_sds_len(auth_header));

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "external_account: impersonation HTTP "
                      "request failed (ret=%d)", ret);
        goto cleanup;
    }

    if (c->resp.status != 200) {
        flb_plg_error(ctx->ins,
                      "external_account: impersonation returned HTTP %d: %.*s",
                      c->resp.status,
                      (int) c->resp.payload_size,
                      c->resp.payload ? c->resp.payload : "");
        goto cleanup;
    }

    rc = wif_parse_impersonation_response(ctx,
                                          c->resp.payload,
                                          c->resp.payload_size,
                                          out_access_token,
                                          out_expires_at);

cleanup:
    if (c) {
        flb_http_client_destroy(c);
    }
    if (conn) {
        flb_upstream_conn_release(conn);
    }
    if (auth_header) {
        flb_sds_destroy(auth_header);
    }
    if (body) {
        flb_sds_destroy(body);
    }
    if (body_str) {
        free(body_str);
    }
    if (body_doc) {
        yyjson_mut_doc_free(body_doc);
    }
    flb_free(prot);
    flb_free(url_host);
    flb_free(url_port);
    flb_free(url_uri);
    return rc;
}

int stackdriver_external_account_read_token(struct flb_stackdriver *ctx)
{
    int rc = -1;
    flb_sds_t subject_token = NULL;
    flb_sds_t federated_access_token = NULL;
    flb_sds_t federated_token_type = NULL;
    flb_sds_t final_access_token = NULL;
    flb_sds_t final_token_type = NULL;
    uint64_t federated_expires_in = 0;
    time_t   final_expires_at = 0;
    time_t   now;
    const char *sts_scope;
    const char *impersonation_url;
    int impersonating;

    if (!ctx->creds) {
        flb_plg_error(ctx->ins, "external_account: missing credentials");
        return -1;
    }
    if (!ctx->creds->audience ||
        flb_sds_len(ctx->creds->audience) == 0 ||
        !ctx->creds->subject_token_type ||
        flb_sds_len(ctx->creds->subject_token_type) == 0) {
        flb_plg_error(ctx->ins, "external_account: 'audience' and "
                      "'subject_token_type' are required");
        return -1;
    }

    impersonation_url = ctx->creds->service_account_impersonation_url;
    impersonating = (impersonation_url &&
                     flb_sds_len(ctx->creds->service_account_impersonation_url) > 0);

    /*
     * When impersonating, the federated token must carry cloud-platform so
     * it can call IAM Credentials. Otherwise we ask STS directly for the
     * narrower scope used by the Stackdriver client.
     */
    sts_scope = impersonating ? FLB_STD_IAM_SCOPE : FLB_STD_SCOPE;

    if (ctx->creds->cred_source_file &&
        flb_sds_len(ctx->creds->cred_source_file) > 0) {
        subject_token = read_subject_token_from_file(ctx);
    }
    else if (ctx->creds->cred_source_url &&
             flb_sds_len(ctx->creds->cred_source_url) > 0) {
        subject_token = read_subject_token_from_url(ctx);
    }
    else {
        flb_plg_error(ctx->ins, "external_account: credential_source must "
                      "provide either 'file' or 'url'");
        return -1;
    }
    if (!subject_token) {
        return -1;
    }

    rc = wif_sts_exchange(ctx,
                          subject_token,
                          sts_scope,
                          &federated_access_token,
                          &federated_token_type,
                          &federated_expires_in);
    if (rc != 0 || !federated_access_token) {
        goto cleanup;
    }

    now = time(NULL);
    if (!impersonating) {
        final_access_token = federated_access_token;
        federated_access_token = NULL;
        final_token_type = federated_token_type;
        federated_token_type = NULL;
        final_expires_at = now + (time_t) federated_expires_in;
    }
    else {
        rc = wif_impersonate(ctx,
                             federated_access_token,
                             FLB_STD_SCOPE,
                             &final_access_token,
                             &final_expires_at);
        if (rc != 0 || !final_access_token) {
            rc = -1;
            goto cleanup;
        }
        final_token_type = flb_sds_create("Bearer");
        if (!final_token_type) {
            flb_errno();
            rc = -1;
            goto cleanup;
        }
    }

    /* Publish the final token into the oauth2 context */
    if (ctx->o->access_token) {
        flb_sds_destroy(ctx->o->access_token);
    }
    if (ctx->o->token_type) {
        flb_sds_destroy(ctx->o->token_type);
    }
    ctx->o->access_token = final_access_token;
    ctx->o->token_type = final_token_type;
    ctx->o->expires_at = final_expires_at;
    ctx->o->expires_in = (final_expires_at > now) ?
                        (uint64_t) (final_expires_at - now) : 0;
    final_access_token = NULL;
    final_token_type = NULL;

    rc = 0;

cleanup:
    if (subject_token) {
        flb_sds_destroy(subject_token);
    }
    if (federated_access_token) {
        flb_sds_destroy(federated_access_token);
    }
    if (federated_token_type) {
        flb_sds_destroy(federated_token_type);
    }
    if (final_access_token) {
        flb_sds_destroy(final_access_token);
    }
    if (final_token_type) {
        flb_sds_destroy(final_token_type);
    }
    return rc;
}
