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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_kv.h>

#include <msgpack.h>

#include "bigquery.h"
#include "bigquery_conf.h"

// TODO: The following code is copied from the Stackdriver plugin and should be
//       factored into common library functions.

/*
 * Base64 Encoding in JWT must:
 *
 * - remove any trailing padding '=' character
 * - replace '+' with '-'
 * - replace '/' with '_'
 *
 * ref: https://www.rfc-editor.org/rfc/rfc7515.txt Appendix C
 */
int bigquery_jwt_base64_url_encode(unsigned char *out_buf, size_t out_size,
                          unsigned char *in_buf, size_t in_size,
                          size_t *olen)

{
    int i;
    size_t len;
    int    result;

    /* do normal base64 encoding */
    result = flb_base64_encode((unsigned char *) out_buf, out_size - 1,
                               &len, in_buf, in_size);
    if (result != 0) {
        return -1;
    }

    /* Replace '+' and '/' characters */
    for (i = 0; i < len && out_buf[i] != '='; i++) {
        if (out_buf[i] == '+') {
            out_buf[i] = '-';
        }
        else if (out_buf[i] == '/') {
            out_buf[i] = '_';
        }
    }

    /* Now 'i' becomes the new length */
    *olen = i;
    return 0;
}

static int bigquery_jwt_encode(struct flb_bigquery *ctx,
                               char *payload, char *secret,
                               char **out_signature, size_t *out_size)
{
    int ret;
    int len;
    int buf_size;
    size_t olen;
    char *buf;
    char *sigd;
    char *headers = "{\"alg\": \"RS256\", \"typ\": \"JWT\"}";
    unsigned char sha256_buf[32] = {0};
    flb_sds_t out;
    unsigned char sig[256] = {0};
    size_t sig_len;

    buf_size = (strlen(payload) + strlen(secret)) * 2;
    buf = flb_malloc(buf_size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    /* Encode header */
    len = strlen(headers);
    ret = flb_base64_encode((unsigned char *) buf, buf_size - 1,
                            &olen, (unsigned char *) headers, len);
    if (ret != 0) {
        flb_free(buf);

        return ret;
    }

    /* Create buffer to store JWT */
    out = flb_sds_create_size(2048);
    if (!out) {
        flb_errno();
        flb_free(buf);
        return -1;
    }

    /* Append header */
    out = flb_sds_cat(out, buf, olen);
    out = flb_sds_cat(out, ".", 1);

    /* Encode Payload */
    len = strlen(payload);
    bigquery_jwt_base64_url_encode((unsigned char *) buf, buf_size,
                          (unsigned char *) payload, len, &olen);

    /* Append Payload */
    out = flb_sds_cat(out, buf, olen);

    /* do sha256() of base64(header).base64(payload) */
    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char *) out, flb_sds_len(out),
                          sha256_buf, sizeof(sha256_buf));

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ctx->ins, "error hashing token");
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    /* In mbedTLS cert length must include the null byte */
    len = strlen(secret) + 1;

    sig_len = sizeof(sig);

    ret = flb_crypto_sign_simple(FLB_CRYPTO_PRIVATE_KEY,
                                 FLB_CRYPTO_PADDING_PKCS1,
                                 FLB_HASH_SHA256,
                                 (unsigned char *) secret, len,
                                 sha256_buf, sizeof(sha256_buf),
                                 sig, &sig_len);

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ctx->ins, "error creating RSA context");
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    sigd = flb_malloc(2048);
    if (!sigd) {
        flb_errno();
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    bigquery_jwt_base64_url_encode((unsigned char *) sigd, 2048, sig, 256, &olen);

    out = flb_sds_cat(out, ".", 1);
    out = flb_sds_cat(out, sigd, olen);

    *out_signature = out;
    *out_size = flb_sds_len(out);

    flb_free(buf);
    flb_free(sigd);

    return 0;
}

/* Create a new oauth2 context and get a oauth2 token */
static int bigquery_get_oauth2_token(struct flb_bigquery *ctx)
{
    int ret;
    char *token;
    char *sig_data;
    size_t sig_size;
    time_t issued;
    time_t expires;
    char payload[1024];

    /* Clear any previous oauth2 payload content */
    flb_oauth2_payload_clear(ctx->o);

    /* JWT encode for oauth2 */
    issued = time(NULL);
    expires = issued + FLB_BIGQUERY_TOKEN_REFRESH;

    snprintf(payload, sizeof(payload) - 1,
             "{\"iss\": \"%s\", \"scope\": \"%s\", "
             "\"aud\": \"%s\", \"exp\": %lu, \"iat\": %lu}",
             ctx->oauth_credentials->client_email, FLB_BIGQUERY_SCOPE,
             FLB_BIGQUERY_AUTH_URL,
             expires, issued);

    /* Compose JWT signature */
    ret = bigquery_jwt_encode(ctx, payload, ctx->oauth_credentials->private_key,
                              &sig_data, &sig_size);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "JWT signature generation failed");
        return -1;
    }

    flb_plg_debug(ctx->ins, "JWT signature:\n%s", sig_data);

    ret = flb_oauth2_payload_append(ctx->o,
                                    "grant_type", -1,
                                    "urn%3Aietf%3Aparams%3Aoauth%3A"
                                    "grant-type%3Ajwt-bearer", -1);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        flb_sds_destroy(sig_data);
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o,
                                    "assertion", -1,
                                    sig_data, sig_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        flb_sds_destroy(sig_data);
        return -1;
    }
    flb_sds_destroy(sig_data);

    /* Retrieve access token */
    token = flb_oauth2_token_get(ctx->o);
    if (!token) {
        flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
        return -1;
    }

    return 0;
}

static flb_sds_t add_aws_signature(struct flb_http_client *c, struct flb_bigquery *ctx) {
    flb_sds_t signature;

    flb_plg_debug(ctx->ins, "Signing the request with AWS SigV4 using IMDS credentials");

    signature = flb_signv4_do(c, FLB_TRUE, FLB_TRUE, time(NULL),
                              ctx->aws_region, "sts",
                              0, NULL, ctx->aws_provider);
    if (!signature) {
        flb_plg_error(ctx->ins, "Could not sign the request with AWS SigV4");
        return NULL;
    }

    return signature;
}

static inline int to_encode_path(char c)
{
    if ((c >= 48 && c <= 57)  ||  /* 0-9 */
        (c >= 65 && c <= 90)  ||  /* A-Z */
        (c >= 97 && c <= 122) ||  /* a-z */
        (c == '-' || c == '_' || c == '.' || c == '~' || c == '/')) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static flb_sds_t uri_encode(const char *uri, size_t len)
{
    int i;
    flb_sds_t buf = NULL;
    flb_sds_t tmp = NULL;

    buf = flb_sds_create_size(len * 2);
    if (!buf) {
        flb_error("[uri_encode] cannot allocate buffer for URI encoding");
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (to_encode_path(uri[i]) == FLB_TRUE) {
            tmp = flb_sds_printf(&buf, "%%%02X", (unsigned char) *(uri + i));
            if (!tmp) {
                flb_error("[uri_encode] error formatting special character");
                flb_sds_destroy(buf);
                return NULL;
            }
            continue;
        }

        /* Direct assignment, just copy the character */
        if (buf) {
            tmp = flb_sds_cat(buf, uri + i, 1);
            if (!tmp) {
                flb_error("[uri_encode] error composing outgoing buffer");
                flb_sds_destroy(buf);
                return NULL;
            }
            buf = tmp;
        }
    }

    return buf;
}

/* https://cloud.google.com/iam/docs/using-workload-identity-federation */
static int bigquery_exchange_aws_creds_for_google_oauth(struct flb_bigquery *ctx)
{
    struct flb_connection *aws_sts_conn;
    struct flb_connection *google_sts_conn = NULL;
    struct flb_connection *google_gen_access_token_conn = NULL;
    struct flb_http_client *aws_sts_c = NULL;
    struct flb_http_client *google_sts_c = NULL;
    struct flb_http_client *google_gen_access_token_c = NULL;
    int google_sts_ret;
    int google_gen_access_token_ret;
    size_t b_sent_google_sts;
    size_t b_sent_google_gen_access_token;
    flb_sds_t signature = NULL;
    flb_sds_t sigv4_amz_date = NULL;
    flb_sds_t sigv4_amz_sec_token = NULL;
    flb_sds_t aws_gci_url = NULL;
    flb_sds_t aws_gci_goog_target_resource = NULL;
    flb_sds_t aws_gci_token = NULL;
    flb_sds_t aws_gci_token_encoded = NULL;
    flb_sds_t google_sts_token = NULL;
    flb_sds_t google_gen_access_token_body = NULL;
    flb_sds_t google_gen_access_token_url = NULL;
    flb_sds_t google_federated_token = NULL;
    flb_sds_t google_auth_header = NULL;

    if (ctx->sa_token) {
        flb_sds_destroy(ctx->sa_token);
        ctx->sa_token = NULL;
    }

    /* Sign an AWS STS request with AWS SigV4 signature */
    aws_sts_conn = flb_upstream_conn_get(ctx->aws_sts_upstream);
    if (!aws_sts_conn) {
        flb_plg_error(ctx->ins, "Failed to get upstream connection for AWS STS");
        goto error;
    }

    aws_sts_c = flb_http_client(aws_sts_conn, FLB_HTTP_POST, FLB_BIGQUERY_AWS_STS_ENDPOINT,
                                NULL, 0, NULL, 0, NULL, 0);
    if (!aws_sts_c) {
        flb_plg_error(ctx->ins, "Failed to create HTTP client for AWS STS");
        goto error;
    }

    signature = add_aws_signature(aws_sts_c, ctx);
    if (!signature) {
        flb_plg_error(ctx->ins, "Failed to sign AWS STS request");
        goto error;
    }

    sigv4_amz_date = flb_sds_create(flb_kv_get_key_value("x-amz-date", &aws_sts_c->headers));
    if (!sigv4_amz_date) {
        flb_plg_error(ctx->ins, "Failed to extract `x-amz-date` header from AWS STS signed request");
        goto error;
    }

    sigv4_amz_sec_token = flb_sds_create(flb_kv_get_key_value("x-amz-security-token", &aws_sts_c->headers));
    if (!sigv4_amz_sec_token) {
        flb_plg_error(ctx->ins, "Failed to extract `x-amz-security-token` header from AWS STS signed request");
        goto error;
    }

    /* Create an AWS GetCallerIdentity token */

    /* AWS STS endpoint URL */
    aws_gci_url = flb_sds_create_size(128);
    aws_gci_url = flb_sds_printf(&aws_gci_url,
                                 "https://%s%s",
                                 ctx->aws_sts_endpoint,
                                 FLB_BIGQUERY_AWS_STS_ENDPOINT);

    /* x-goog-cloud-target-resource header */
    aws_gci_goog_target_resource = flb_sds_create_size(128);
    aws_gci_goog_target_resource = flb_sds_printf(&aws_gci_goog_target_resource,
                                                  FLB_BIGQUERY_GOOGLE_CLOUD_TARGET_RESOURCE,
                                                  ctx->project_number, ctx->pool_id, ctx->provider_id);

    aws_gci_token = flb_sds_create_size(2048);
    aws_gci_token = flb_sds_printf(
            &aws_gci_token,
            "{\"url\":\"%s\",\"method\":\"POST\",\"headers\":["
            "{\"key\":\"Authorization\",\"value\":\"%s\"},"
            "{\"key\":\"host\",\"value\":\"%s\"},"
            "{\"key\":\"x-amz-date\",\"value\":\"%s\"},"
            "{\"key\":\"x-goog-cloud-target-resource\",\"value\":\"%s\"},"
            "{\"key\":\"x-amz-security-token\",\"value\":\"%s\"}"
            "]}",
            aws_gci_url,
            signature,
            ctx->aws_sts_endpoint,
            sigv4_amz_date,
            aws_gci_goog_target_resource,
            sigv4_amz_sec_token);

    aws_gci_token_encoded = uri_encode(aws_gci_token, flb_sds_len(aws_gci_token));
    if (!aws_gci_token_encoded) {
        flb_plg_error(ctx->ins, "Failed to encode GetCallerIdentity token");
        goto error;
    }

    /* To exchange the AWS credential for a federated access token,
     * we need to pass the AWS GetCallerIdentity token to the Google Security Token Service's token() method */
    google_sts_token = flb_sds_create_size(2048);
    google_sts_token = flb_sds_printf(
            &google_sts_token,
            "{\"audience\":\"%s\","
            "\"grantType\":\"%s\","
            "\"requestedTokenType\":\"%s\","
            "\"scope\":\"%s\","
            "\"subjectTokenType\":\"%s\","
            "\"subjectToken\":\"%s\"}",
            aws_gci_goog_target_resource,
            FLB_BIGQUERY_GOOGLE_STS_TOKEN_GRANT_TYPE,
            FLB_BIGQUERY_GOOGLE_STS_TOKEN_REQUESTED_TOKEN_TYPE,
            FLB_BIGQUERY_GOOGLE_STS_TOKEN_SCOPE,
            FLB_BIGQUERY_GOOGLE_STS_TOKEN_SUBJECT_TOKEN_TYPE,
            aws_gci_token_encoded);

    google_sts_conn = flb_upstream_conn_get(ctx->google_sts_upstream);
    if (!google_sts_conn) {
        flb_plg_error(ctx->ins, "Google STS connection setup failed");
        goto error;
    }

    google_sts_c = flb_http_client(google_sts_conn, FLB_HTTP_POST, FLB_BIGQUERY_GOOGLE_CLOUD_TOKEN_ENDPOINT,
                                   google_sts_token, flb_sds_len(google_sts_token),
                                   NULL, 0, NULL, 0);

    google_sts_ret = flb_http_do(google_sts_c, &b_sent_google_sts);
    if (google_sts_ret != 0) {
        flb_plg_error(ctx->ins, "Google STS token request http_do=%i", google_sts_ret);
        goto error;
    }

    if (google_sts_c->resp.status != 200) {
        flb_plg_error(ctx->ins, "Google STS token response status: %i, payload:\n%s",
                      google_sts_c->resp.status, google_sts_c->resp.payload);
        goto error;
    }

    /* To exchange the federated token for a service account access token,
     * we need to call the Google Service Account Credentials API generateAccessToken() method */
    google_federated_token = flb_json_get_val(google_sts_c->resp.payload,
                                              google_sts_c->resp.payload_size,
                                              "access_token");
    if (!google_federated_token) {
        flb_plg_error(ctx->ins, "Failed to extract Google federated access token from STS token() response");
        goto error;
    }

    google_gen_access_token_conn = flb_upstream_conn_get(ctx->google_iam_upstream);
    if (!google_gen_access_token_conn) {
        flb_plg_error(ctx->ins, "Google Service Account Credentials API connection setup failed");
        goto error;
    }

    google_gen_access_token_url = flb_sds_create_size(256);
    google_gen_access_token_url = flb_sds_printf(&google_gen_access_token_url,
                                                 FLB_BIGQUERY_GOOGLE_GEN_ACCESS_TOKEN_URL,
                                                 ctx->google_service_account);

    google_gen_access_token_body = flb_sds_create(FLB_BIGQUERY_GOOGLE_GEN_ACCESS_TOKEN_REQUEST_BODY);

    google_gen_access_token_c = flb_http_client(google_gen_access_token_conn, FLB_HTTP_POST, google_gen_access_token_url,
                                                google_gen_access_token_body, flb_sds_len(google_gen_access_token_body),
                                                NULL, 0, NULL, 0);

    google_auth_header = flb_sds_create_size(2048 + 7);
    google_auth_header = flb_sds_printf(&google_auth_header, "%s%s",
                                        "Bearer ", google_federated_token);

    flb_http_add_header(google_gen_access_token_c, "Authorization", 13,
                        google_auth_header, flb_sds_len(google_auth_header));

    flb_http_add_header(google_gen_access_token_c, "Content-Type", 12,
                        "application/json; charset=utf-8", 31);

    google_gen_access_token_ret = flb_http_do(google_gen_access_token_c, &b_sent_google_gen_access_token);
    if (google_gen_access_token_ret != 0) {
        flb_plg_error(ctx->ins, "Google Service Account Credentials API generateAccessToken() request http_do=%i",
                      google_gen_access_token_ret);
        goto error;
    }

    if (google_gen_access_token_c->resp.status != 200) {
        flb_plg_error(ctx->ins, "Google Service Account Credentials API generateAccessToken() response "
                                "status: %i, payload:\n%s",
                      google_gen_access_token_c->resp.status, google_gen_access_token_c->resp.payload);
        goto error;
    }

    ctx->sa_token = flb_json_get_val(google_gen_access_token_c->resp.payload,
                                     google_gen_access_token_c->resp.payload_size,
                                     "accessToken");
    if (!ctx->sa_token) {
        flb_plg_error(ctx->ins, "Failed to extract Google OAuth token "
                                "from Service Account Credentials API generateAccessToken() response");
        goto error;
    }

    ctx->sa_token_expiry = time(NULL) + FLB_BIGQUERY_TOKEN_REFRESH;

    flb_sds_destroy(signature);
    flb_sds_destroy(sigv4_amz_date);
    flb_sds_destroy(sigv4_amz_sec_token);
    flb_sds_destroy(aws_gci_url);
    flb_sds_destroy(aws_gci_goog_target_resource);
    flb_sds_destroy(aws_gci_token);
    flb_sds_destroy(aws_gci_token_encoded);
    flb_sds_destroy(google_sts_token);
    flb_sds_destroy(google_gen_access_token_body);
    flb_sds_destroy(google_gen_access_token_url);
    flb_sds_destroy(google_federated_token);
    flb_sds_destroy(google_auth_header);

    flb_http_client_destroy(aws_sts_c);
    flb_http_client_destroy(google_sts_c);
    flb_http_client_destroy(google_gen_access_token_c);

    flb_upstream_conn_release(aws_sts_conn);
    flb_upstream_conn_release(google_sts_conn);
    flb_upstream_conn_release(google_gen_access_token_conn);

    flb_plg_info(ctx->ins, "Retrieved Google service account OAuth token via Identity Federation");

    return 0;

error:
    flb_sds_destroy(signature);
    flb_sds_destroy(sigv4_amz_date);
    flb_sds_destroy(sigv4_amz_sec_token);
    flb_sds_destroy(aws_gci_url);
    flb_sds_destroy(aws_gci_goog_target_resource);
    flb_sds_destroy(aws_gci_token);
    flb_sds_destroy(aws_gci_token_encoded);
    flb_sds_destroy(google_sts_token);
    flb_sds_destroy(google_gen_access_token_body);
    flb_sds_destroy(google_gen_access_token_url);
    flb_sds_destroy(google_federated_token);
    flb_sds_destroy(google_auth_header);

    if (aws_sts_c) {
        flb_http_client_destroy(aws_sts_c);
    }

    if (google_sts_c) {
        flb_http_client_destroy(google_sts_c);
    }

    if (google_gen_access_token_c) {
        flb_http_client_destroy(google_gen_access_token_c);
    }

    if (aws_sts_conn) {
        flb_upstream_conn_release(aws_sts_conn);
    }

    if (google_sts_conn) {
        flb_upstream_conn_release(google_sts_conn);
    }

    if (google_gen_access_token_conn) {
        flb_upstream_conn_release(google_gen_access_token_conn);
    }

    return -1;
}

static int flb_bigquery_google_token_expired(time_t expiry)
{
    time_t now;

    now = time(NULL);
    if (expiry <= now) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static flb_sds_t get_google_service_account_token(struct flb_bigquery *ctx) {
    int ret = 0;
    flb_sds_t output;
    flb_plg_trace(ctx->ins, "Getting Google service account token");

    if (!ctx->sa_token) {
        flb_plg_trace(ctx->ins, "Acquiring new token");
        ret = bigquery_exchange_aws_creds_for_google_oauth(ctx);
    }
    else if (flb_bigquery_google_token_expired(ctx->sa_token_expiry) == FLB_TRUE) {
        flb_plg_trace(ctx->ins, "Replacing expired token");
        ret = bigquery_exchange_aws_creds_for_google_oauth(ctx);
    }

    if (ret != 0) {
        return NULL;
    }

    output = flb_sds_create_size(2048 + 7);
    output = flb_sds_printf(&output, "%s%s", "Bearer ", ctx->sa_token);
    return output;
}

static flb_sds_t get_google_token(struct flb_bigquery *ctx)
{
    int ret = 0;
    flb_sds_t output = NULL;

    if (pthread_mutex_lock(&ctx->token_mutex)){
        flb_plg_error(ctx->ins, "error locking mutex");
        return NULL;
    }

    if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
        ret = bigquery_get_oauth2_token(ctx);
    }

    /* Copy string to prevent race conditions (get_oauth2 can free the string) */
    if (ret == 0) {
        output = flb_sds_create(ctx->o->token_type);
        flb_sds_printf(&output, " %s", ctx->o->access_token);
    }

    if (pthread_mutex_unlock(&ctx->token_mutex)){
        flb_plg_error(ctx->ins, "error unlocking mutex");
        if (output) {
            flb_sds_destroy(output);
        }
        return NULL;
    }

    return output;
}

static int cb_bigquery_init(struct flb_output_instance *ins,
                            struct flb_config *config, void *data)
{
    char *token;
    int io_flags = FLB_IO_TLS;
    struct flb_bigquery *ctx;

    /* Create config context */
    ctx = flb_bigquery_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    flb_output_set_context(ins, ctx);

    /* Network mode IPv6 */
    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Create mutex for acquiring oauth tokens (they are shared across flush coroutines) */
    pthread_mutex_init(&ctx->token_mutex, NULL);

    /*
     * Create upstream context for BigQuery Streaming Inserts
     * (no oauth2 service)
     */
    ctx->u = flb_upstream_create_url(config, FLB_BIGQUERY_URL_BASE,
                                     io_flags, ins->tls);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "upstream creation failed");
        return -1;
    }

    if (ctx->has_identity_federation) {
        /* Configure AWS IMDS */
        ctx->aws_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                      FLB_TRUE,
                                      ins->tls_debug,
                                      ins->tls_vhost,
                                      ins->tls_ca_path,
                                      ins->tls_ca_file,
                                      ins->tls_crt_file,
                                      ins->tls_key_file,
                                      ins->tls_key_passwd,
                                      ins->verifier_ins);

        if (!ctx->aws_tls) {
            flb_plg_error(ctx->ins, "Failed to create TLS context");
            flb_bigquery_conf_destroy(ctx);
            return -1;
        }

        ctx->aws_provider = flb_standard_chain_provider_create(config,
                                                               ctx->aws_tls,
                                                               NULL,
                                                               NULL,
                                                               NULL,
                                                               flb_aws_client_generator(),
                                                               NULL);

        if (!ctx->aws_provider) {
            flb_plg_error(ctx->ins, "Failed to create AWS Credential Provider");
            flb_bigquery_conf_destroy(ctx);
            return -1;
        }

        /* initialize credentials in sync mode */
        ctx->aws_provider->provider_vtable->sync(ctx->aws_provider);
        ctx->aws_provider->provider_vtable->init(ctx->aws_provider);

        /* set back to async */
        ctx->aws_provider->provider_vtable->async(ctx->aws_provider);
        ctx->aws_provider->provider_vtable->upstream_set(ctx->aws_provider, ctx->ins);

        /* Configure AWS STS */
        ctx->aws_sts_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                          FLB_TRUE,
                                          ins->tls_debug,
                                          ins->tls_vhost,
                                          ins->tls_ca_path,
                                          ins->tls_ca_file,
                                          ins->tls_crt_file,
                                          ins->tls_key_file,
                                          ins->tls_key_passwd,
                                          ins->verifier_ins);

        if (!ctx->aws_sts_tls) {
            flb_plg_error(ctx->ins, "Failed to create TLS context");
            flb_bigquery_conf_destroy(ctx);
            return -1;
        }

        ctx->aws_sts_upstream = flb_upstream_create(config,
                                                    ctx->aws_sts_endpoint,
                                                    443,
                                                    io_flags,
                                                    ctx->aws_sts_tls);

        if (!ctx->aws_sts_upstream) {
            flb_plg_error(ctx->ins, "AWS STS upstream creation failed");
            flb_bigquery_conf_destroy(ctx);
            return -1;
        }

        ctx->aws_sts_upstream->base.net.keepalive = FLB_FALSE;

        /* Configure Google STS */
        ctx->google_sts_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                             FLB_TRUE,
                                             ins->tls_debug,
                                             ins->tls_vhost,
                                             ins->tls_ca_path,
                                             ins->tls_ca_file,
                                             ins->tls_crt_file,
                                             ins->tls_key_file,
                                             ins->tls_key_passwd,
                                             ins->verifier_ins);

        if (!ctx->google_sts_tls) {
            flb_plg_error(ctx->ins, "Failed to create TLS context");
            flb_bigquery_conf_destroy(ctx);
            return -1;
        }

        ctx->google_sts_upstream = flb_upstream_create_url(config,
                                                           FLB_BIGQUERY_GOOGLE_STS_URL,
                                                           io_flags,
                                                           ctx->google_sts_tls);

        if (!ctx->google_sts_upstream) {
            flb_plg_error(ctx->ins, "Google STS upstream creation failed");
            flb_bigquery_conf_destroy(ctx);
            return -1;
        }

        /* Configure Google IAM */
        ctx->google_iam_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                             FLB_TRUE,
                                             ins->tls_debug,
                                             ins->tls_vhost,
                                             ins->tls_ca_path,
                                             ins->tls_ca_file,
                                             ins->tls_crt_file,
                                             ins->tls_key_file,
                                             ins->tls_key_passwd,
                                             ins->verifier_ins);

        if (!ctx->google_iam_tls) {
            flb_plg_error(ctx->ins, "Failed to create TLS context");
            flb_bigquery_conf_destroy(ctx);
            return -1;
        }

        ctx->google_iam_upstream = flb_upstream_create_url(config,
                                                           FLB_BIGQUERY_GOOGLE_IAM_URL,
                                                           io_flags,
                                                           ctx->google_iam_tls);

        if (!ctx->google_iam_upstream) {
            flb_plg_error(ctx->ins, "Google IAM upstream creation failed");
            flb_bigquery_conf_destroy(ctx);
            return -1;
        }

        /* Remove async flag from upstream */
        flb_stream_disable_async_mode(&ctx->aws_sts_upstream->base);
        flb_stream_disable_async_mode(&ctx->google_sts_upstream->base);
        flb_stream_disable_async_mode(&ctx->google_iam_upstream->base);
    }

    /* Create oauth2 context */
    ctx->o = flb_oauth2_create(ctx->config, FLB_BIGQUERY_AUTH_URL, 3000);
    if (!ctx->o) {
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        return -1;
    }
    flb_output_upstream_set(ctx->u, ins);

    /* Get or renew the OAuth2 token */
    if (ctx->has_identity_federation) {
        token = get_google_service_account_token(ctx);
    }
    else {
        token = get_google_token(ctx);
    }

    if (!token) {
        flb_plg_warn(ctx->ins, "token retrieval failed");
    }
    else {
        flb_sds_destroy(token);
    }

    return 0;
}

static int bigquery_format(const void *data, size_t bytes,
                           const char *tag, size_t tag_len,
                           char **out_data, size_t *out_size,
                           struct flb_bigquery *ctx,
                           struct flb_config *config)
{
    int array_size = 0;
    flb_sds_t out_buf;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    array_size = flb_mp_count(data, bytes);

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Pack root map (kind & rows):
     *
     * {
     *   "kind": "bigquery#tableDataInsertAllRequest",
     *   "skipInvalidRows": boolean,
     *   "ignoreUnknownValues": boolean,
     *   "rows": []
     * }
     */
    msgpack_pack_map(&mp_pck, 4);

    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "kind", 4);

    msgpack_pack_str(&mp_pck, 34);
    msgpack_pack_str_body(&mp_pck, "bigquery#tableDataInsertAllRequest", 34);

    msgpack_pack_str(&mp_pck, 15);
    msgpack_pack_str_body(&mp_pck, "skipInvalidRows", 15);

    if (ctx->skip_invalid_rows) {
        msgpack_pack_true(&mp_pck);
    }
    else {
        msgpack_pack_false(&mp_pck);
    }

    msgpack_pack_str(&mp_pck, 19);
    msgpack_pack_str_body(&mp_pck, "ignoreUnknownValues", 19);

    if (ctx->ignore_unknown_values) {
        msgpack_pack_true(&mp_pck);
    }
    else {
        msgpack_pack_false(&mp_pck);
    }

    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "rows", 4);

    /* Append entries */
    msgpack_pack_array(&mp_pck, array_size);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        /*
         * Pack entry
         *
         * {
         *  "json": {...}
         * }
         *
         * For now, we don't support the insertId that's required for duplicate detection.
         */
        msgpack_pack_map(&mp_pck, 1);

        /* json */
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "json", 4);
        msgpack_pack_object(&mp_pck, *log_event.body);
    }

    /* Convert from msgpack to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                          config->json_escape_unicode);

    flb_log_event_decoder_destroy(&log_decoder);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        flb_plg_error(ctx->ins, "error formatting JSON payload");
        return -1;
    }

    *out_data = out_buf;
    *out_size = flb_sds_len(out_buf);

    return 0;
}

static void cb_bigquery_flush(struct flb_event_chunk *event_chunk,
                              struct flb_output_flush *out_flush,
                              struct flb_input_instance *i_ins,
                              void *out_context,
                              struct flb_config *config)
{
    (void) i_ins;
    (void) config;
    int ret;
    int ret_code = FLB_RETRY;
    size_t b_sent;
    flb_sds_t token;
    flb_sds_t payload_buf;
    size_t payload_size;
    struct flb_bigquery *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    flb_plg_trace(ctx->ins, "flushing bytes %zu", event_chunk->size);

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Get or renew Token */
    if (ctx->has_identity_federation) {
        token = get_google_service_account_token(ctx);
    }
    else {
        token = get_google_token(ctx);
    }

    if (!token) {
        flb_plg_error(ctx->ins, "cannot retrieve oauth2 token");
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Reformat msgpack to bigquery JSON payload */
    ret = bigquery_format(event_chunk->data, event_chunk->size,
                          event_chunk->tag, flb_sds_len(event_chunk->tag),
                          &payload_buf, &payload_size, ctx, config);
    if (ret != 0) {
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(token);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        payload_buf, payload_size, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(token);
        flb_sds_destroy(payload_buf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_http_buffer_size(c, 4192);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);

    /* Compose and append Authorization header */
    flb_http_add_header(c, "Authorization", 13, token, flb_sds_len(token));

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* validate response */
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        ret_code = FLB_RETRY;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_plg_debug(ctx->ins, "HTTP Status=%i", c->resp.status);
        if (c->resp.status == 200) {
            ret_code = FLB_OK;
        }
        else {
            if (c->resp.payload && c->resp.payload_size > 0) {
                /* we got an error */
                flb_plg_warn(ctx->ins, "response\n%s", c->resp.payload);
            }
            ret_code = FLB_RETRY;
        }
    }

    /* Cleanup */
    flb_sds_destroy(payload_buf);
    flb_sds_destroy(token);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    /* Done */
    FLB_OUTPUT_RETURN(ret_code);
}

static int cb_bigquery_exit(void *data, struct flb_config *config)
{
    struct flb_bigquery *ctx = data;

    if (!ctx) {
        return -1;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_bigquery_conf_destroy(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "google_service_credentials", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_bigquery, credentials_file),
     "Set the path for the google service credentials file"
    },
    {
     FLB_CONFIG_MAP_BOOL, "enable_identity_federation", "false",
     0, FLB_TRUE, offsetof(struct flb_bigquery, has_identity_federation),
     "Enable identity federation"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_region", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_bigquery, aws_region),
     "Enable identity federation"
    },
    {
      FLB_CONFIG_MAP_STR, "project_number", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_bigquery, project_number),
      "Set project number"
    },
    {
      FLB_CONFIG_MAP_STR, "pool_id", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_bigquery, pool_id),
      "Set the pool id"
    },
    {
      FLB_CONFIG_MAP_STR, "provider_id", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_bigquery, provider_id),
      "Set the provider id"
    },
    {
      FLB_CONFIG_MAP_STR, "google_service_account", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_bigquery, google_service_account),
      "Set the google service account"
    },
    // set in flb_bigquery_oauth_credentials
    {
      FLB_CONFIG_MAP_STR, "service_account_email", (char *)NULL,
      0, FLB_FALSE, 0,
      "Set the service account email"
    },
    // set in flb_bigquery_oauth_credentials
    {
      FLB_CONFIG_MAP_STR, "service_account_secret", (char *)NULL,
      0, FLB_FALSE, 0,
      "Set the service account secret"
    },
    {
      FLB_CONFIG_MAP_STR, "project_id", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_bigquery, project_id),
      "Set the project id"
    },
    {
      FLB_CONFIG_MAP_STR, "dataset_id", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_bigquery, dataset_id),
      "Set the dataset id"
    },
    {
      FLB_CONFIG_MAP_STR, "table_id", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_bigquery, table_id),
      "Set the table id"
    },
    {
      FLB_CONFIG_MAP_BOOL, "skip_invalid_rows", "false",
      0, FLB_TRUE, offsetof(struct flb_bigquery, skip_invalid_rows),
      "Enable skipping of invalid rows",
    },
    {
      FLB_CONFIG_MAP_BOOL, "ignore_unknown_values", "false",
      0, FLB_TRUE, offsetof(struct flb_bigquery, ignore_unknown_values),
      "Enable ignoring unknown value",
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_bigquery_plugin = {
    .name         = "bigquery",
    .description  = "Send events to BigQuery via streaming insert",
    .cb_init      = cb_bigquery_init,
    .cb_flush     = cb_bigquery_flush,
    .cb_exit      = cb_bigquery_exit,
    .config_map   = config_map,
    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
