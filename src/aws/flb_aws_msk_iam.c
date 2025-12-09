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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_hmac.h>
#include <fluent-bit/flb_kafka.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/aws/flb_aws_msk_iam.h>
#include <fluent-bit/tls/flb_tls.h>

#include <fluent-bit/flb_signv4.h>
#include <rdkafka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/*
 * OAuth token lifetime of 5 minutes (industry standard).
 * Matches AWS Go SDK and Kafka Connect implementations.
 */
#define MSK_IAM_TOKEN_LIFETIME_SECONDS 300

struct flb_aws_msk_iam {
    struct flb_config *flb_config;
    flb_sds_t region;
    int is_serverless;  /* Flag to indicate if this is MSK Serverless */
    struct flb_tls *cred_tls;
    struct flb_aws_provider *provider;
    pthread_mutex_t lock;  /* Protects credential provider access from concurrent threads */
};

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

    buf = flb_sds_create_size(len * 3 + 1);
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

    hex = flb_sds_create_size(65);
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

/* Extract region from MSK broker address
 * Supported formats:
 * - MSK Standard: b-1.example.c1.kafka.<Region>.amazonaws.com:port
 * - MSK Serverless: boot-<ClusterUniqueID>.c<x>.kafka-serverless.<Region>.amazonaws.com:port
 * - VPC Endpoint: vpce-<ID>.kafka.<Region>.vpce.amazonaws.com:port
 */
static flb_sds_t extract_region_from_broker(const char *broker)
{
    const char *p;
    const char *start;
    const char *end;
    const char *port_pos;
    size_t len;
    flb_sds_t out;
    
    if (!broker || strlen(broker) == 0) {
        return NULL;
    }
    
    /* Remove port if present (e.g., :9098) */
    port_pos = strchr(broker, ':');
    if (port_pos) {
        len = port_pos - broker;
    } else {
        len = strlen(broker);
    }
    
    /* Find .amazonaws.com */
    p = strstr(broker, ".amazonaws.com");
    if (!p || p >= broker + len) {
        return NULL;
    }
    
    /* Region is between the last dot before .amazonaws.com and .amazonaws.com
     * Handle VPC endpoints (vpce-xxx.kafka.region.vpce.amazonaws.com)
     * Example formats:
     *   Standard: ...kafka.us-east-1.amazonaws.com
     *   Serverless: ...kafka-serverless.us-east-1.amazonaws.com
     *   VPC Endpoint: ...kafka.us-east-1.vpce.amazonaws.com
     */
    end = p;  /* Points to .amazonaws.com */
    
    /* Check for VPC endpoint format: .vpce.amazonaws.com */
    if (p >= broker + 5 && strncmp(p - 5, ".vpce", 5) == 0) {
        /* For VPC endpoints, region ends at .vpce */
        end = p - 5;
    }
    
    /* Find the start of region by going backwards to find the previous dot */
    start = end - 1;
    while (start > broker && *start != '.') {
        start--;
    }
    
    if (*start == '.') {
        start++;  /* Skip the dot */
    }
    
    if (start >= end) {
        return NULL;
    }
    
    len = end - start;
    
    /* Sanity check on region length (AWS regions are typically 9-20 chars) */
    if (len == 0 || len > 32) {
        return NULL;
    }
    
    out = flb_sds_create_len(start, len);
    if (!out) {
        return NULL;
    }
    
    return out;
}

/* Payload generator - builds MSK IAM authentication payload */
static flb_sds_t build_msk_iam_payload(struct flb_aws_msk_iam *config,
                                       const char *host,
                                       struct flb_aws_credentials *creds)
{
    flb_sds_t payload = NULL;
    int encode_result;
    char *p;
    size_t len;
    size_t url_len;
    size_t encoded_len;
    size_t actual_encoded_len;
    size_t final_len;
    flb_sds_t credential = NULL;
    flb_sds_t credential_enc = NULL;
    flb_sds_t query = NULL;
    flb_sds_t canonical = NULL;
    flb_sds_t hexhash = NULL;
    flb_sds_t string_to_sign = NULL;
    flb_sds_t hexsig = NULL;
    flb_sds_t key = NULL;
    flb_sds_t tmp = NULL;
    flb_sds_t session_token_enc = NULL;
    flb_sds_t action_enc = NULL;
    flb_sds_t presigned_url = NULL;
    flb_sds_t empty_payload_hex = NULL;
    char amzdate[32];
    char datestamp[16];
    unsigned char sha256_buf[32];
    unsigned char key_date[32];
    unsigned char key_region[32];
    unsigned char key_service[32];
    unsigned char key_signing[32];
    unsigned char sig[32];
    unsigned char empty_payload_hash[32];
    struct tm gm;
    time_t now;

    now = time(NULL);

    /* Validate inputs */
    if (!config || !config->region || flb_sds_len(config->region) == 0) {
        flb_error("[aws_msk_iam] region is not set or invalid");
        return NULL;
    }

    if (!host || strlen(host) == 0) {
        flb_error("[aws_msk_iam] host is required");
        return NULL;
    }

    if (!creds || !creds->access_key_id || !creds->secret_access_key) {
        flb_error("[aws_msk_iam] invalid or incomplete credentials");
        return NULL;
    }

    gmtime_r(&now, &gm);
    strftime(amzdate, sizeof(amzdate) - 1, "%Y%m%dT%H%M%SZ", &gm);
    strftime(datestamp, sizeof(datestamp) - 1, "%Y%m%d", &gm);

    /* Build credential string */
    credential = flb_sds_create_size(256);
    if (!credential) {
        goto error;
    }

    credential = flb_sds_printf(&credential, "%s/%s/%s/kafka-cluster/aws4_request",
                               creds->access_key_id, datestamp, config->region);
    if (!credential) {
        goto error;
    }

    credential_enc = uri_encode_params(credential, flb_sds_len(credential));
    if (!credential_enc) {
        goto error;
    }

    action_enc = uri_encode_params("kafka-cluster:Connect", 21);
    if (!action_enc) {
        goto error;
    }

    /* Build canonical query string */
    query = flb_sds_create_size(8192);
    if (!query) {
        goto error;
    }

    query = flb_sds_printf(&query,
                          "Action=%s&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s"
                          "&X-Amz-Date=%s&X-Amz-Expires=900",
                          action_enc, credential_enc, amzdate);
    if (!query) {
        goto error;
    }

    /* Add session token if present */
    if (creds->session_token && flb_sds_len(creds->session_token) > 0) {
        session_token_enc = uri_encode_params(creds->session_token,
                                              flb_sds_len(creds->session_token));
        if (!session_token_enc) {
            goto error;
        }

        tmp = flb_sds_printf(&query, "&X-Amz-Security-Token=%s", session_token_enc);
        if (!tmp) {
            goto error;
        }
        query = tmp;
    }

    tmp = flb_sds_printf(&query, "&X-Amz-SignedHeaders=host");
    if (!tmp) {
        goto error;
    }
    query = tmp;

    /* Build canonical request */
    canonical = flb_sds_create_size(16384);
    if (!canonical) {
        goto error;
    }

    if (flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) "", 0, empty_payload_hash,
                       sizeof(empty_payload_hash)) != FLB_CRYPTO_SUCCESS) {
        goto error;
    }

    empty_payload_hex = sha256_to_hex(empty_payload_hash);
    if (!empty_payload_hex) {
        goto error;
    }

    canonical = flb_sds_printf(&canonical,
                              "GET\n/\n%s\nhost:%s\n\nhost\n%s",
                              query, host, empty_payload_hex);

    flb_sds_destroy(empty_payload_hex);
    empty_payload_hex = NULL;
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
    string_to_sign = flb_sds_create_size(2048);
    if (!string_to_sign) {
        goto error;
    }

    string_to_sign = flb_sds_printf(&string_to_sign,
                                   "AWS4-HMAC-SHA256\n%s\n%s/%s/kafka-cluster/aws4_request\n%s",
                                   amzdate, datestamp, config->region, hexhash);
    if (!string_to_sign) {
        goto error;
    }

    /* Derive signing key */
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
        goto error;
    }

    flb_sds_destroy(key);
    key = NULL;

    len = strlen(config->region);
    if (hmac_sha256_sign(key_region, key_date, 32, (unsigned char *) config->region, len) != 0) {
        goto error;
    }

    if (hmac_sha256_sign(key_service, key_region, 32, (unsigned char *) "kafka-cluster", 13) != 0) {
        goto error;
    }

    if (hmac_sha256_sign(key_signing, key_service, 32,
                        (unsigned char *) "aws4_request", 12) != 0) {
        goto error;
    }

    if (hmac_sha256_sign(sig, key_signing, 32,
                        (unsigned char *) string_to_sign, flb_sds_len(string_to_sign)) != 0) {
        goto error;
    }

    hexsig = sha256_to_hex(sig);
    if (!hexsig) {
        goto error;
    }

    tmp = flb_sds_printf(&query, "&X-Amz-Signature=%s", hexsig);
    if (!tmp) {
        goto error;
    }
    query = tmp;

    /* Build complete presigned URL */
    presigned_url = flb_sds_create_size(16384);
    if (!presigned_url) {
        goto error;
    }

    presigned_url = flb_sds_printf(&presigned_url, "https://%s/?%s&User-Agent=fluent-bit-msk-iam", 
                                   host, query);
    if (!presigned_url) {
        goto error;
    }

    /* Base64 URL encode */
    url_len = flb_sds_len(presigned_url);
    encoded_len = ((url_len + 2) / 3) * 4 + 1;

    payload = flb_sds_create_size(encoded_len);
    if (!payload) {
        goto error;
    }

    encode_result = flb_base64_encode((unsigned char*) payload, encoded_len, &actual_encoded_len,
                                     (const unsigned char *) presigned_url, url_len);
    if (encode_result == -1) {
        goto error;
    }

    flb_sds_len_set(payload, actual_encoded_len);

    /* Convert to Base64 URL encoding and remove padding */
    p = payload;
    while (*p) {
        if (*p == '+') {
            *p = '-';
        }
        else if (*p == '/') {
            *p = '_';
        }
        p++;
    }

    final_len = flb_sds_len(payload);
    while (final_len > 0 && payload[final_len-1] == '=') {
        final_len--;
    }
    flb_sds_len_set(payload, final_len);
    payload[final_len] = '\0';

    /* Clean up */
    flb_sds_destroy(credential);
    flb_sds_destroy(credential_enc);
    flb_sds_destroy(canonical);
    flb_sds_destroy(hexhash);
    flb_sds_destroy(string_to_sign);
    flb_sds_destroy(hexsig);
    flb_sds_destroy(query);
    flb_sds_destroy(action_enc);
    flb_sds_destroy(presigned_url);
    if (session_token_enc) {
        flb_sds_destroy(session_token_enc);
    }

    return payload;

error:
    if (credential) flb_sds_destroy(credential);
    if (credential_enc) flb_sds_destroy(credential_enc);
    if (canonical) flb_sds_destroy(canonical);
    if (hexhash) flb_sds_destroy(hexhash);
    if (string_to_sign) flb_sds_destroy(string_to_sign);
    if (hexsig) flb_sds_destroy(hexsig);
    if (query) flb_sds_destroy(query);
    if (action_enc) flb_sds_destroy(action_enc);
    if (presigned_url) flb_sds_destroy(presigned_url);
    if (key) flb_sds_destroy(key);
    if (payload) flb_sds_destroy(payload);
    if (session_token_enc) flb_sds_destroy(session_token_enc);
    if (empty_payload_hex) flb_sds_destroy(empty_payload_hex);

    return NULL;
}

/* OAuth token refresh callback */
static void oauthbearer_token_refresh_cb(rd_kafka_t *rk,
                                         const char *oauthbearer_config,
                                         void *opaque)
{
    char host[256];
    flb_sds_t payload = NULL;
    rd_kafka_resp_err_t err;
    char errstr[512];
    time_t now;
    int64_t md_lifetime_ms;
    struct flb_aws_msk_iam *config;
    struct flb_aws_credentials *creds = NULL;
    struct flb_kafka_opaque *kafka_opaque;
    (void) oauthbearer_config;

    kafka_opaque = (struct flb_kafka_opaque *) opaque;
    if (!kafka_opaque || !kafka_opaque->msk_iam_ctx) {
        flb_error("[aws_msk_iam] invalid opaque context");
        rd_kafka_oauthbearer_set_token_failure(rk, "invalid context");
        return;
    }

    config = kafka_opaque->msk_iam_ctx;

    if (!config->region || flb_sds_len(config->region) == 0) {
        flb_error("[aws_msk_iam] region is not set");
        rd_kafka_oauthbearer_set_token_failure(rk, "region not set");
        return;
    }

    /* Determine MSK endpoint based on cluster type */
    if (config->is_serverless) {
        snprintf(host, sizeof(host), "kafka-serverless.%s.amazonaws.com", config->region);
    }
    else {
        snprintf(host, sizeof(host), "kafka.%s.amazonaws.com", config->region);
    }

    flb_debug("[aws_msk_iam] OAuth token refresh callback triggered");

    /*
     * CRITICAL CONCURRENCY FIX:
     * Lock the credential provider to prevent race conditions.
     * The librdkafka refresh callback executes in its internal thread context,
     * while Fluent Bit may access the same provider from other threads.
     * Without synchronization, concurrent refresh/get_credentials calls can
     * corrupt provider state and cause authentication failures.
     */
    pthread_mutex_lock(&config->lock);

    /* Refresh credentials */
    if (config->provider->provider_vtable->refresh(config->provider) < 0) {
        pthread_mutex_unlock(&config->lock);
        flb_warn("[aws_msk_iam] credential refresh failed, will retry on next callback");
        rd_kafka_oauthbearer_set_token_failure(rk, "credential refresh failed");
        return;
    }

    /* Get credentials */
    creds = config->provider->provider_vtable->get_credentials(config->provider);
    if (!creds) {
        pthread_mutex_unlock(&config->lock);
        flb_error("[aws_msk_iam] failed to get AWS credentials from provider");
        rd_kafka_oauthbearer_set_token_failure(rk, "credential retrieval failed");
        return;
    }

    /* Unlock immediately after getting credentials - no need to hold lock during payload generation */
    pthread_mutex_unlock(&config->lock);

    /* Generate payload */
    payload = build_msk_iam_payload(config, host, creds);
    if (!payload) {
        flb_error("[aws_msk_iam] failed to generate MSK IAM payload");
        flb_aws_credentials_destroy(creds);
        rd_kafka_oauthbearer_set_token_failure(rk, "payload generation failed");
        return;
    }

    /*
     * Set OAuth token with fixed 5-minute lifetime (AWS industry standard).
     * librdkafka's background thread will automatically trigger a refresh callback
     * at 80% of the token's lifetime (4 minutes) to ensure the token never expires,
     * even on completely idle connections.
     */
    now = time(NULL);
    md_lifetime_ms = ((int64_t)now + MSK_IAM_TOKEN_LIFETIME_SECONDS) * 1000;

    err = rd_kafka_oauthbearer_set_token(rk,
                                        payload,
                                        md_lifetime_ms,
                                        creds->access_key_id,
                                        NULL,
                                        0,
                                        errstr,
                                        sizeof(errstr));

    flb_aws_credentials_destroy(creds);

    if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
        flb_error("[aws_msk_iam] failed to set OAuth bearer token: %s", errstr);
        rd_kafka_oauthbearer_set_token_failure(rk, errstr);
    }
    else {
        flb_info("[aws_msk_iam] OAuth bearer token refreshed");
    }

    if (payload) {
        flb_sds_destroy(payload);
    }
}

/* Register OAuth callback */
struct flb_aws_msk_iam *flb_aws_msk_iam_register_oauth_cb(struct flb_config *config,
                                                          rd_kafka_conf_t *kconf,
                                                          struct flb_kafka_opaque *opaque,
                                                          const char *brokers)
{
    struct flb_aws_msk_iam *ctx;
    flb_sds_t region_str = NULL;
    char *first_broker = NULL;
    char *comma;

    /* Validate inputs */
    if (!opaque) {
        flb_error("[aws_msk_iam] opaque context is required");
        return NULL;
    }

    if (!brokers || strlen(brokers) == 0) {
        flb_error("[aws_msk_iam] brokers configuration is required for region extraction");
        return NULL;
    }
    
    /* Extract first broker from comma-separated list */
    first_broker = flb_strdup(brokers);
    if (!first_broker) {
        flb_error("[aws_msk_iam] failed to allocate memory for broker parsing");
        return NULL;
    }
    
    comma = strchr(first_broker, ',');
    if (comma) {
        *comma = '\0';  /* Terminate at first comma */
    }
    
    /* Extract region from broker address */
    region_str = extract_region_from_broker(first_broker);
    if (!region_str || flb_sds_len(region_str) == 0) {
        flb_error("[aws_msk_iam] failed to extract region from broker address: %s", 
                 brokers);
        flb_free(first_broker);
        if (region_str) {
            flb_sds_destroy(region_str);
        }
        return NULL;
    }
    
    /* Detect if this is MSK Serverless by checking broker address */
    ctx = flb_calloc(1, sizeof(struct flb_aws_msk_iam));
    if (!ctx) {
        flb_errno();
        flb_free(first_broker);
        flb_sds_destroy(region_str);
        return NULL;
    }

    ctx->flb_config = config;
    ctx->region = region_str;
    
    /* Detect cluster type (Standard vs Serverless) */
    if (strstr(first_broker, ".kafka-serverless.")) {
        ctx->is_serverless = 1;
        flb_info("[aws_msk_iam] detected MSK Serverless cluster");
    }
    else {
        ctx->is_serverless = 0;
    }
    
    flb_free(first_broker);
    first_broker = NULL;
    
    flb_info("[aws_msk_iam] detected %s MSK cluster, region: %s", 
             ctx->is_serverless ? "Serverless" : "Standard",
             region_str);

    /* Create TLS instance */
    ctx->cred_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                    FLB_TRUE,
                                    0,  /* TLS debug off by default */
                                    NULL, NULL, NULL, NULL, NULL, NULL);
    if (!ctx->cred_tls) {
        flb_error("[aws_msk_iam] failed to create TLS instance");
        flb_sds_destroy(ctx->region);
        flb_free(ctx);
        return NULL;
    }

    /* Create AWS provider */
    ctx->provider = flb_standard_chain_provider_create(config,
                                                       ctx->cred_tls,
                                                       ctx->region,
                                                       NULL, NULL,
                                                       flb_aws_client_generator(),
                                                       NULL);
    if (!ctx->provider) {
        flb_error("[aws_msk_iam] failed to create AWS credentials provider");
        flb_tls_destroy(ctx->cred_tls);
        flb_sds_destroy(ctx->region);
        flb_free(ctx);
        return NULL;
    }

    /* Initialize provider */
    ctx->provider->provider_vtable->sync(ctx->provider);
    if (ctx->provider->provider_vtable->init(ctx->provider) != 0) {
        flb_error("[aws_msk_iam] failed to initialize AWS credentials provider");
        /* provider owns cred_tls, will destroy it */
        flb_aws_provider_destroy(ctx->provider);
        ctx->cred_tls = NULL;
        flb_sds_destroy(ctx->region);
        flb_free(ctx);
        return NULL;
    }
    ctx->provider->provider_vtable->async(ctx->provider);

    /* Initialize mutex to protect credential provider access from concurrent threads */
    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        flb_error("[aws_msk_iam] failed to initialize credential provider mutex");
        /* provider owns cred_tls, will destroy it */
        flb_aws_provider_destroy(ctx->provider);
        ctx->cred_tls = NULL;
        flb_sds_destroy(ctx->region);
        flb_free(ctx);
        return NULL;
    }

    /*
     * Set MSK IAM context in opaque - now opaque->msk_iam_ctx only holds
     * struct flb_aws_msk_iam * throughout its lifetime, eliminating type confusion.
     */
    flb_kafka_opaque_set(opaque, NULL, ctx);
    rd_kafka_conf_set_opaque(kconf, opaque);
    
    /* Register OAuth token refresh callback */
    rd_kafka_conf_set_oauthbearer_token_refresh_cb(kconf, oauthbearer_token_refresh_cb);

    return ctx;
}

/* Destroy MSK IAM config */
void flb_aws_msk_iam_destroy(struct flb_aws_msk_iam *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->provider) {
        /* Provider owns and destroys cred_tls, don't destroy again */
        flb_aws_provider_destroy(ctx->provider);
    }
    else if (ctx->cred_tls) {
        /* Only destroy cred_tls if provider creation failed */
        flb_tls_destroy(ctx->cred_tls);
    }
    
    if (ctx->region) {
        flb_sds_destroy(ctx->region);
    }

    /* Destroy the credential provider mutex */
    pthread_mutex_destroy(&ctx->lock);
    
    flb_free(ctx);
}
