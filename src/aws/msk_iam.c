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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_hmac.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_signv4.h>
#include <rdkafka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fluent-bit/aws/msk_iam.h>

/* Wrapper for storing plugin context and MSK IAM state */
struct flb_aws_msk_iam {
    struct flb_aws_provider *provider;
    flb_sds_t region;
    flb_sds_t cluster_arn;
};


/* Utility functions copied from flb_signv4.c */
static int to_encode(char c)
{
    if ((c >= '0' && c <= '9') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z') ||
        c == '_' || c == '-' || c == '~' || c == '.') {
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

static flb_sds_t uri_encode_params(const char *uri, size_t len)
{
    int i;
    flb_sds_t buf = NULL;
    flb_sds_t tmp = NULL;

    buf = flb_sds_create_size(len * 2);
    if (!buf) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (to_encode(uri[i]) == FLB_TRUE || uri[i] == '/') {
            tmp = flb_sds_printf(&buf, "%%%02X", (unsigned char) uri[i]);
            if (!tmp) {
                flb_sds_destroy(buf);
                return NULL;
            }
            buf = tmp;
            continue;
        }
        tmp = flb_sds_cat(buf, uri + i, 1);
        if (!tmp) {
            flb_sds_destroy(buf);
            return NULL;
        }
        buf = tmp;
    }
    return buf;
}

static flb_sds_t sha256_to_hex(unsigned char *sha256)
{
    int i;
    flb_sds_t hex;
    flb_sds_t tmp;

    hex = flb_sds_create_size(64);
    if (!hex) {
        return NULL;
    }

    for (i = 0; i < 32; i++) {
        tmp = flb_sds_printf(&hex, "%02x", sha256[i]);
        if (!tmp) {
            flb_sds_destroy(hex);
            return NULL;
        }
        hex = tmp;
    }
    return hex;
}

static int hmac_sha256_sign(unsigned char out[32],
                            unsigned char *key, size_t key_len,
                            unsigned char *msg, size_t msg_len)
{
    int result;

    result = flb_hmac_simple(FLB_HASH_SHA256,
                             key, key_len,
                             msg, msg_len,
                             out, 32);
    if (result != FLB_CRYPTO_SUCCESS) {
        return -1;
    }
    return 0;
}

static flb_sds_t build_presigned_query(struct flb_aws_msk_iam *ctx,
                                       const char *host,
                                       time_t now)
{
    struct flb_aws_credentials *creds;
    struct tm gm;
    char amzdate[32];
    char datestamp[16];
    flb_sds_t credential = NULL;
    flb_sds_t credential_enc = NULL;
    flb_sds_t query = NULL;
    flb_sds_t canonical = NULL;
    unsigned char sha256_buf[32];
    flb_sds_t hexhash = NULL;
    flb_sds_t string_to_sign = NULL;
    unsigned char key_date[32];
    unsigned char key_region[32];
    unsigned char key_service[32];
    unsigned char key_signing[32];
    unsigned char sig[32];
    flb_sds_t hexsig = NULL;
    flb_sds_t token = NULL;
    int len;
    int klen = 32;
    flb_sds_t tmp;
    flb_sds_t session_token_enc = NULL;

    if (!ctx || !ctx->region || strlen(ctx->region) == 0) {
        flb_error("[msk_iam] build_presigned_query: region is not set or invalid");
        return NULL;
    }

    creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
    if (!creds) {
        return NULL;
    }

    gmtime_r(&now, &gm);
    strftime(amzdate, sizeof(amzdate) - 1, "%Y%m%dT%H%M%SZ", &gm);
    strftime(datestamp, sizeof(datestamp) - 1, "%Y%m%d", &gm);

    /* Build credential string */
    credential = flb_sds_create_size(128);
    if (!credential) {
        goto error;
    }

    credential = flb_sds_printf(&credential, "%s/%s/%s/sts/aws4_request",
                                creds->access_key_id, datestamp, ctx->region);
    if (!credential) {
        goto error;
    }
    credential_enc = uri_encode_params(credential, flb_sds_len(credential));
    if (!credential_enc) {
        goto error;
    }

    /* Build initial query string */
    query = flb_sds_create_size(256);
    if (!query) {
        goto error;
    }

    query = flb_sds_printf(&query,
                           "Action=GetCallerIdentity&Version=2011-06-15"
                           "&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s"
                           "&X-Amz-Date=%s&X-Amz-Expires=900&X-Amz-SignedHeaders=host",
                           credential_enc, amzdate);
    if (!query) {
        goto error;
    }

    /* Add session token if present */
    if (creds->session_token) {
        session_token_enc = uri_encode_params(creds->session_token,
                                              flb_sds_len(creds->session_token));
        if (!session_token_enc) {
            goto error;
        }
        tmp = flb_sds_printf(&query, "&X-Amz-Security-Token=%s", session_token_enc);
        if (!tmp) {
            goto error;
        }
        flb_sds_destroy(session_token_enc);
        session_token_enc = NULL;
        query = tmp;
    }

    /* Build canonical request */
    canonical = flb_sds_create_size(512);
    if (!canonical) {
        goto error;
    }

    canonical = flb_sds_printf(&canonical,
                               "GET\n/\n%s\nhost:%s\n\nhost\nUNSIGNED-PAYLOAD",
                               query, host);
    if (!canonical) {
        goto error;
    }

    /* Hash canonical request */
    if (flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) canonical,
                        flb_sds_len(canonical), sha256_buf,
                        sizeof(sha256_buf)) != FLB_CRYPTO_SUCCESS) {
        goto error;
    }

    hexhash = sha256_to_hex(sha256_buf);
    if (!hexhash) {
        goto error;
    }

    /* Build string to sign */
    string_to_sign = flb_sds_create_size(512);
    if (!string_to_sign) {
        goto error;
    }

    string_to_sign = flb_sds_printf(&string_to_sign,
                                    "AWS4-HMAC-SHA256\n%s\n%s/%s/sts/aws4_request\n%s",
                                    amzdate, datestamp, ctx->region, hexhash);
    if (!string_to_sign) {
        goto error;
    }

    /* Derive signing key */
    flb_sds_t key;
    key = flb_sds_create_size(128);
    if (!key) {
        goto error;
    }

    key = flb_sds_printf(&key, "AWS4%s", creds->secret_access_key);
    if (!key) {
        goto error;
    }
    len = strlen(datestamp);
    if (hmac_sha256_sign(key_date, (unsigned char *) key, flb_sds_len(key),
                         (unsigned char *) datestamp, len) != 0) {
        flb_sds_destroy(key);
        goto error;
    }
    flb_sds_destroy(key);

    len = strlen(ctx->region);
    if (hmac_sha256_sign(key_region, key_date, klen, (unsigned char *) ctx->region, len) != 0) {
        goto error;
    }

    if (hmac_sha256_sign(key_service, key_region, klen, (unsigned char *) "sts", 3) != 0) {
        goto error;
    }

    if (hmac_sha256_sign(key_signing, key_service, klen,
                         (unsigned char *) "aws4_request", 12) != 0) {
        goto error;
    }

    if (hmac_sha256_sign(sig, key_signing, klen,
                         (unsigned char *) string_to_sign, flb_sds_len(string_to_sign)) != 0) {
        goto error;
    }

    hexsig = sha256_to_hex(sig);
    if (!hexsig) {
        goto error;
    }

    /* Append signature to query */
    tmp = flb_sds_printf(&query, "&X-Amz-Signature=%s", hexsig);
    if (!tmp) {
        goto error;
    }
    query = tmp;

    /* Return a copy of the query as the token */
    token = flb_sds_create(query);

    /* Clean up */
    flb_sds_destroy(credential);
    flb_sds_destroy(credential_enc);
    flb_sds_destroy(canonical);
    flb_sds_destroy(hexhash);
    flb_sds_destroy(string_to_sign);
    flb_sds_destroy(hexsig);
    flb_sds_destroy(query); /* Only destroy the temporary, not the returned token */
    flb_aws_credentials_destroy(creds);
    return token;

error:
    flb_sds_destroy(credential);
    flb_sds_destroy(credential_enc);
    flb_sds_destroy(canonical);
    flb_sds_destroy(hexhash);
    flb_sds_destroy(string_to_sign);
    flb_sds_destroy(hexsig);
    flb_sds_destroy(query);
    flb_sds_destroy(session_token_enc);
    flb_aws_credentials_destroy(creds);
    return NULL;
}

static void oauthbearer_token_refresh_cb(rd_kafka_t *rk,
                                         const char *oauthbearer_config,
                                         void *opaque)
{
    struct flb_msk_iam_cb *cb;
    struct flb_aws_msk_iam *ctx;
    flb_sds_t token = NULL;
    char host[256];
    rd_kafka_resp_err_t err;
    char errstr[256];

    (void) oauthbearer_config;

    printf("[msk_iam] oauthbearer_token_refresh_cb invoked\n");
    cb = rd_kafka_opaque(rk);
    if (!cb || !cb->iam) {
        printf("[msk_iam] oauthbearer_token_refresh_cb called with no context\n");
        rd_kafka_oauthbearer_set_token_failure(rk, "no context");
        return;
    }

    ctx = cb->iam;
    if (!ctx->region || strlen(ctx->region) == 0) {
        flb_error("[msk_iam] oauthbearer_token_refresh_cb: region is not set or invalid");
        rd_kafka_oauthbearer_set_token_failure(rk, "region not set");
        return;
    }
    snprintf(host, sizeof(host) - 1, "sts.%s.amazonaws.com", ctx->region);

    printf("[msk_iam] oauthbearer_token_refresh_cb: requesting token from region %s\n", ctx->region);
    token = build_presigned_query(ctx, host, time(NULL));
    if (!token) {
        flb_error("[msk_iam] failed to generate MSK IAM token");
        rd_kafka_oauthbearer_set_token_failure(rk, "token error");
        return;
    }

    printf("[msk_iam] oauthbearer_token_refresh_cb: retrieved token: '%s'\n", token);
    char *b = strdup(token);

const char *principal = "admin"; // or whatever is appropriate for your setup

    err = rd_kafka_oauthbearer_set_token(
        rk,
        b,                                   // token_value
        ((int64_t)time(NULL) + 900) * 1000,  // md_lifetime_ms
        principal,                           // md_principal_name (MANDATORY)
        NULL,                                // extensions
        0,                                   // extension_size
        errstr,                              // errstr
        sizeof(errstr)                       // errstr_size
    );

    if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
        flb_error("[msk_iam] rd_kafka_oauthbearer_set_token failed: %s", errstr);
    }
    else {
        flb_debug("[msk_iam] MSK IAM token refreshed");
    }

    //flb_sds_destroy(token);
}

static char *extract_region(const char *arn)
{
    const char *p;
    const char *r;
    size_t len;
    char *out;

    /* arn:partition:service:region:... */
    p = strchr(arn, ':');
    if (!p) {
        return NULL;
    }
    p = strchr(p + 1, ':');
    if (!p) {
        return NULL;
    }
    p = strchr(p + 1, ':');
    if (!p) {
        return NULL;
    }

    r = p + 1;
    p = strchr(r, ':');
    if (!p) {
        return NULL;
    }
    len = p - r;
    out = flb_malloc(len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, r, len);
    out[len] = '\0';
    return out;
}

struct flb_aws_msk_iam *flb_aws_msk_iam_register_oauth_cb(struct flb_config *config,
                                                          rd_kafka_conf_t *kconf,
                                                          const char *cluster_arn,
                                                          void *owner)
{
    struct flb_aws_msk_iam *ctx;
    struct flb_msk_iam_cb *cb;

    flb_info("[ED] entered flb_aws_msk_iam_register_oauth_cb with cluster ARN: %s",
             cluster_arn);
    if (!cluster_arn) {
        return NULL;
    }

    ctx = flb_calloc(1, sizeof(struct flb_aws_msk_iam));
    if (!ctx) {
        return NULL;
    }

    ctx->cluster_arn = flb_sds_create(cluster_arn);
    ctx->region = extract_region(cluster_arn);
    if (!ctx->region) {
        flb_error("[msk_iam] failed to extract region from cluster ARN: %s", cluster_arn);
        flb_free(ctx);
        return NULL;
    }

    ctx->provider = flb_standard_chain_provider_create(config, NULL,
                                                       ctx->region, NULL, NULL,
                                                       flb_aws_client_generator(),
                                                       NULL);
    if (!ctx->provider) {
        flb_sds_destroy(ctx->region);
        flb_sds_destroy(ctx->cluster_arn);
        flb_free(ctx);
        return NULL;
    }

    ctx->provider->provider_vtable->init(ctx->provider);

    cb = flb_calloc(1, sizeof(struct flb_msk_iam_cb));
    if (!cb) {
        flb_aws_msk_iam_destroy(ctx);
        return NULL;
    }
    cb->plugin_ctx = owner;
    cb->iam = ctx;

    rd_kafka_conf_set_oauthbearer_token_refresh_cb(kconf,
                                                   oauthbearer_token_refresh_cb);
    rd_kafka_conf_set_opaque(kconf, cb);

    return ctx;
}

void flb_aws_msk_iam_destroy(struct flb_aws_msk_iam *ctx)
{
    if (!ctx) {
        return;
    }
    if (ctx->provider) {
        ctx->provider->provider_vtable->destroy(ctx->provider);
    }
    flb_sds_destroy(ctx->region);
    flb_sds_destroy(ctx->cluster_arn);
    flb_free(ctx);
}

void flb_aws_msk_iam_cb_destroy(struct flb_msk_iam_cb *cb)
{
    if (!cb) {
        return;
    }
    flb_aws_msk_iam_destroy(cb->iam);
    flb_free(cb);
}

