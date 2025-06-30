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

    buf = flb_sds_create_size(len * 3 + 1);  /* Increased multiplier for safety */
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

    hex = flb_sds_create_size(65);  /* 64 + 1 for null terminator */
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

    /* Add validation */
    if (!ctx || !ctx->region || flb_sds_len(ctx->region) == 0) {
        flb_error("[msk_iam] build_presigned_query: region is not set or invalid");
        return NULL;
    }

    if (!host || strlen(host) == 0) {
        flb_error("[msk_iam] build_presigned_query: host is required");
        return NULL;
    }

    /* CRITICAL: Log BEFORE starting canonical request construction */
    flb_info("[msk_iam] build_presigned_query: generating token for host: %s, region: %s",
             host, ctx->region);

    creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
    if (!creds) {
        flb_error("[msk_iam] build_presigned_query: failed to get credentials");
        return NULL;
    }

    if (!creds->access_key_id || !creds->secret_access_key) {
        flb_error("[msk_iam] build_presigned_query: incomplete credentials");
        flb_aws_credentials_destroy(creds);
        return NULL;
    }

    /* CRITICAL: Log BEFORE starting canonical request construction */
    flb_info("[msk_iam] build_presigned_query: using access key: %.10s...", creds->access_key_id);

    gmtime_r(&now, &gm);
    strftime(amzdate, sizeof(amzdate) - 1, "%Y%m%dT%H%M%SZ", &gm);
    strftime(datestamp, sizeof(datestamp) - 1, "%Y%m%d", &gm);

    /* CRITICAL: Log BEFORE starting canonical request construction */
    flb_info("[msk_iam] build_presigned_query: timestamp: %s, date: %s", amzdate, datestamp);

    /* Build credential string */
    credential = flb_sds_create_size(256);
    if (!credential) {
        goto error;
    }

    credential = flb_sds_printf(&credential, "%s/%s/%s/kafka-cluster/aws4_request",
                            creds->access_key_id, datestamp, ctx->region);
    if (!credential) {
        goto error;
    }

    /* CRITICAL: Log BEFORE starting canonical request construction */
    flb_info("[msk_iam] build_presigned_query: credential scope: %s", credential);

    credential_enc = uri_encode_params(credential, flb_sds_len(credential));
    if (!credential_enc) {
        goto error;
    }

    /* Build initial query string - INCREASED BUFFER SIZE significantly for large session tokens */
    query = flb_sds_create_size(8192);  /* Increased from 2048 to handle very large session tokens */
    if (!query) {
        goto error;
    }

    /* Build query parameters in ALPHABETICAL ORDER per AWS SigV4 spec */
    query = flb_sds_printf(&query,
                           "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s"
                           "&X-Amz-Date=%s&X-Amz-Expires=900",
                           credential_enc, amzdate);
    if (!query) {
        goto error;
    }

    /* Add session token if present (before SignedHeaders alphabetically) */
    if (creds->session_token && flb_sds_len(creds->session_token) > 0) {
        /* CRITICAL: Log BEFORE encoding - NO LOGGING DURING ENCODING */
        flb_info("[msk_iam] build_presigned_query: adding session token (length: %zu)",
                 flb_sds_len(creds->session_token));

        session_token_enc = uri_encode_params(creds->session_token,
                                              flb_sds_len(creds->session_token));
        if (!session_token_enc) {
            flb_error("[msk_iam] build_presigned_query: failed to encode session token");
            goto error;
        }

        /* CRITICAL: Log AFTER encoding but BEFORE canonical request */
        flb_info("[msk_iam] build_presigned_query: encoded session token length: %zu",
                 flb_sds_len(session_token_enc));

        tmp = flb_sds_printf(&query, "&X-Amz-Security-Token=%s", session_token_enc);
        if (!tmp) {
            flb_error("[msk_iam] build_presigned_query: failed to append session token to query");
            goto error;
        }
        query = tmp;
    }

    /* Add SignedHeaders LAST (alphabetically after Security-Token) */
    tmp = flb_sds_printf(&query, "&X-Amz-SignedHeaders=host");
    if (!tmp) {
        flb_error("[msk_iam] build_presigned_query: failed to append SignedHeaders");
        goto error;
    }
    query = tmp;

    /* CRITICAL: Log BEFORE canonical request construction - NO MORE LOGGING UNTIL AFTER HASH */
    flb_info("[msk_iam] build_presigned_query: query string length: %zu", flb_sds_len(query));

    /* Build canonical request - INCREASED BUFFER SIZE significantly */
    canonical = flb_sds_create_size(16384);  /* Increased from 2048 to handle large query strings */
    if (!canonical) {
        goto error;
    }

    /* CRITICAL: NO LOGGING BETWEEN HERE AND HASH CALCULATION */
    canonical = flb_sds_printf(&canonical,
                                "GET\n/\n%s\nhost:%s\nx-amz-date:%s\nx-amz-security-token:%s\n\n"
                                "host;x-amz-date;x-amz-security-token\nUNSIGNED-PAYLOAD",
                                query, host, amzdate, creds->session_token);

    if (!canonical) {
        flb_error("[msk_iam] build_presigned_query: failed to build canonical request");
        goto error;
    }

    /* Hash canonical request IMMEDIATELY - NO LOGGING BETWEEN CONSTRUCTION AND HASH */
    if (flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) canonical,
                        flb_sds_len(canonical), sha256_buf,
                        sizeof(sha256_buf)) != FLB_CRYPTO_SUCCESS) {
        flb_error("[msk_iam] build_presigned_query: failed to hash canonical request");
        goto error;
    }

    hexhash = sha256_to_hex(sha256_buf);
    if (!hexhash) {
        goto error;
    }

    /* NOW it's safe to log again */
    flb_info("[msk_iam] build_presigned_query: canonical request length: %zu", flb_sds_len(canonical));
    flb_info("[msk_iam] build_presigned_query: canonical request hash: %s", hexhash);

    /* Build string to sign - INCREASED BUFFER SIZE */
    string_to_sign = flb_sds_create_size(2048);  /* Increased from 1024 */
    if (!string_to_sign) {
        goto error;
    }

    string_to_sign = flb_sds_printf(&string_to_sign,
                                    "AWS4-HMAC-SHA256\n%s\n%s/%s/kafka-cluster/aws4_request\n%s",
                                    amzdate, datestamp, ctx->region, hexhash);
    if (!string_to_sign) {
        goto error;
    }

    flb_info("[msk_iam] build_presigned_query: string to sign created");

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
        flb_error("[msk_iam] build_presigned_query: failed to sign date");
        flb_sds_destroy(key);
        goto error;
    }
    flb_sds_destroy(key);

    len = strlen(ctx->region);
    if (hmac_sha256_sign(key_region, key_date, klen, (unsigned char *) ctx->region, len) != 0) {
        flb_error("[msk_iam] build_presigned_query: failed to sign region");
        goto error;
    }

    if (hmac_sha256_sign(key_service, key_region, klen, (unsigned char *) "kafka-cluster", 13) != 0) {
        flb_error("[msk_iam] build_presigned_query: failed to sign service");
        goto error;
    }

    if (hmac_sha256_sign(key_signing, key_service, klen,
                        (unsigned char *) "aws4_request", 12) != 0) {
        flb_error("[msk_iam] build_presigned_query: failed to create signing key");
        goto error;
    }

    if (hmac_sha256_sign(sig, key_signing, klen,
                         (unsigned char *) string_to_sign, flb_sds_len(string_to_sign)) != 0) {
        flb_error("[msk_iam] build_presigned_query: failed to sign request");
        goto error;
    }

    hexsig = sha256_to_hex(sig);
    if (!hexsig) {
        goto error;
    }

    flb_info("[msk_iam] build_presigned_query: signature: %s", hexsig);

    /* Append signature to query */
    tmp = flb_sds_printf(&query, "&X-Amz-Signature=%s;x-amz-date;x-amz-security-token", hexsig);
    if (!tmp) {
        goto error;
    }
    query = tmp;

    /* Return a copy of the query as the token */
    token = flb_sds_create(query);
    if (!token) {
        flb_error("[msk_iam] build_presigned_query: failed to create token copy");
        goto error;
    }

    flb_info("[msk_iam] build_presigned_query: generated token length: %zu", flb_sds_len(token));

    /* Clean up */
    flb_sds_destroy(credential);
    flb_sds_destroy(credential_enc);
    flb_sds_destroy(canonical);
    flb_sds_destroy(hexhash);
    flb_sds_destroy(string_to_sign);
    flb_sds_destroy(hexsig);
    flb_sds_destroy(query);
    if (session_token_enc) {
        flb_sds_destroy(session_token_enc);
    }
    flb_aws_credentials_destroy(creds);
    return token;

error:
    flb_error("[msk_iam] build_presigned_query: error occurred during token generation");
    flb_sds_destroy(credential);
    flb_sds_destroy(credential_enc);
    flb_sds_destroy(canonical);
    flb_sds_destroy(hexhash);
    flb_sds_destroy(string_to_sign);
    flb_sds_destroy(hexsig);
    flb_sds_destroy(query);
    if (session_token_enc) {
        flb_sds_destroy(session_token_enc);
    }
    if (creds) {
        flb_aws_credentials_destroy(creds);
    }
    return NULL;
}

static void oauthbearer_token_refresh_cb(rd_kafka_t *rk,
                                         const char *oauthbearer_config,
                                         void *opaque)
{
    struct flb_msk_iam_cb *cb;
    struct flb_aws_msk_iam *ctx;
    struct flb_aws_credentials *creds = NULL;
    flb_sds_t token = NULL;
    char *token_copy = NULL;
    char host[256];
    rd_kafka_resp_err_t err;
    char errstr[512];
    int64_t now;
    int64_t md_lifetime_ms;

    (void) oauthbearer_config;

    flb_info("[msk_iam] *** OAuth bearer token refresh callback INVOKED ***");

    cb = rd_kafka_opaque(rk);
    if (!cb || !cb->iam) {
        flb_error("[msk_iam] callback invoked with no context");
        rd_kafka_oauthbearer_set_token_failure(rk, "no context");
        return;
    }

    ctx = cb->iam;
    if (!ctx->region || flb_sds_len(ctx->region) == 0) {
        flb_error("[msk_iam] region is not set or invalid");
        rd_kafka_oauthbearer_set_token_failure(rk, "region not set");
        return;
    }

    /* Resolve correct hostname for signing */
    if (cb->broker_host && strlen(cb->broker_host) > 0) {
        strncpy(host, cb->broker_host, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
        flb_info("[msk_iam] Using broker hostname for signing: %s", host);
    } else {
        snprintf(host, sizeof(host), "kafka.%s.amazonaws.com", ctx->region);
        flb_warn("[msk_iam] broker_host not set, using fallback: %s", host);
    }

    flb_info("[msk_iam] requesting token for region: %s, host: %s", ctx->region, host);

    token = build_presigned_query(ctx, host, time(NULL));
    if (!token) {
        flb_error("[msk_iam] failed to generate MSK IAM token");
        rd_kafka_oauthbearer_set_token_failure(rk, "token generation failed");
        return;
    }

    // Print curl command for local testing
    sleep(2);
    printf("[msk_iam] TEST TOKEN:\ncurl \"https://%s/?%s\"\n", host, token);
    // Print principal (access key id)
    if (ctx->provider) {
        struct flb_aws_credentials *test_creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
        if (test_creds && test_creds->access_key_id) {
            printf("[msk_iam] TEST PRINCIPAL: %s\n", test_creds->access_key_id);
            flb_aws_credentials_destroy(test_creds);
        }
    }
    exit(0);

    token_copy = strdup(token);
    if (!token_copy) {
        flb_error("[msk_iam] failed to duplicate token string");
        rd_kafka_oauthbearer_set_token_failure(rk, "memory allocation failed");
        goto cleanup;
    }

    creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
    if (!creds || !creds->access_key_id) {
        flb_error("[msk_iam] failed to retrieve AWS credentials for principal");
        rd_kafka_oauthbearer_set_token_failure(rk, "credential retrieval failed");
        goto cleanup;
    }

    now = (int64_t)time(NULL);
    md_lifetime_ms = (now + 900) * 1000;

    flb_info("[msk_iam] setting OAuth token with principal: %s", creds->access_key_id);
    flb_info("[msk_iam] token length: %zu", strlen(token_copy));

    err = rd_kafka_oauthbearer_set_token(
        rk,
        token_copy,
        md_lifetime_ms,
        creds->access_key_id,
        NULL,
        0,
        errstr,
        sizeof(errstr)
    );

    if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
        flb_error("[msk_iam] failed to set OAuth bearer token: %s", errstr);
        rd_kafka_oauthbearer_set_token_failure(rk, errstr);
    } else {
        flb_info("[msk_iam] OAuth bearer token successfully set");
    }

cleanup:
    if (creds) {
        flb_aws_credentials_destroy(creds);
    }
    if (token) {
        flb_sds_destroy(token);
    }
    // token_copy is managed by librdkafka
}

static void oauthbearer_token_refresh_cb_old(rd_kafka_t *rk,
                                         const char *oauthbearer_config,
                                         void *opaque)
{
    struct flb_msk_iam_cb *cb;
    struct flb_aws_msk_iam *ctx;
    struct flb_aws_credentials *creds = NULL;
    flb_sds_t token = NULL;
    char *token_copy = NULL;
    char host[256];
    rd_kafka_resp_err_t err;
    char errstr[512];
    int64_t now;
    int64_t md_lifetime_ms;

    (void) oauthbearer_config;

    flb_info("[msk_iam] *** OAuth bearer token refresh callback INVOKED ***");

    cb = rd_kafka_opaque(rk);
    if (!cb || !cb->iam) {
        flb_error("[msk_iam] callback invoked with no context");
        rd_kafka_oauthbearer_set_token_failure(rk, "no context");
        return;
    }

    ctx = cb->iam;
    if (!ctx->region || flb_sds_len(ctx->region) == 0) {
        flb_error("[msk_iam] region is not set or invalid");
        rd_kafka_oauthbearer_set_token_failure(rk, "region not set");
        return;
    }

    /* Determine the correct hostname based on cluster type */
    if (ctx->cluster_arn && strstr(ctx->cluster_arn, "-s3") != NULL) {
        /* MSK Serverless cluster - use the generic serverless endpoint */
        snprintf(host, sizeof(host), "kafka-serverless.%s.amazonaws.com", ctx->region);
        cb->broker_host = flb_strdup("boot-53h6572i.c3.kafka-serverless.us-east-2.amazonaws.com");  // add this line
        flb_info("[msk_iam] Detected MSK Serverless cluster, using host: %s", host);
    } else {
        /* Regular MSK cluster - use your existing broker_host mechanism */
        if (cb->broker_host && strlen(cb->broker_host) > 0) {
            strncpy(host, cb->broker_host, sizeof(host) - 1);
            host[sizeof(host) - 1] = '\0';
            flb_info("[msk_iam] Detected regular MSK cluster, using broker host: %s", host);
        } else {
            /* Fallback to generic endpoint if broker host not available */
            snprintf(host, sizeof(host), "kafka.%s.amazonaws.com", ctx->region);
            flb_info("[msk_iam] No broker host available, using generic host: %s", host);
        }
    }

    flb_info("[msk_iam] requesting token for region: %s, host: %s", ctx->region, host);

    token = build_presigned_query(ctx, host, time(NULL));
    if (!token) {
        flb_error("[msk_iam] failed to generate MSK IAM token");
        rd_kafka_oauthbearer_set_token_failure(rk, "token generation failed");
        return;
    }

    // Print curl command for local testing
    printf("[msk_iam] TEST TOKEN: curl 'https://%s/?%s'\n", host, token);
    // Print principal (access key id)
    if (ctx->provider) {
        struct flb_aws_credentials *test_creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
        if (test_creds && test_creds->access_key_id) {
            printf("[msk_iam] TEST PRINCIPAL: %s\n", test_creds->access_key_id);
            flb_aws_credentials_destroy(test_creds);
        }
    }

    token_copy = strdup(token);
    if (!token_copy) {
        flb_error("[msk_iam] failed to duplicate token string");
        rd_kafka_oauthbearer_set_token_failure(rk, "memory allocation failed");
        goto cleanup;
    }

    creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
    if (!creds || !creds->access_key_id) {
        flb_error("[msk_iam] failed to retrieve AWS credentials for principal");
        rd_kafka_oauthbearer_set_token_failure(rk, "credential retrieval failed");
        goto cleanup;
    }

    now = (int64_t)time(NULL);
    md_lifetime_ms = (now + 900) * 1000;

    flb_info("[msk_iam] setting OAuth token with principal: %s", creds->access_key_id);
    flb_info("[msk_iam] token length: %zu", strlen(token_copy));

    err = rd_kafka_oauthbearer_set_token(
        rk,
        token_copy,
        md_lifetime_ms,
        creds->access_key_id,
        NULL,
        0,
        errstr,
        sizeof(errstr)
    );

    if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
        flb_error("[msk_iam] failed to set OAuth bearer token: %s", errstr);
        rd_kafka_oauthbearer_set_token_failure(rk, errstr);
    } else {
        flb_info("[msk_iam] OAuth bearer token successfully set");
    }

cleanup:
    if (creds) {
        flb_aws_credentials_destroy(creds);
    }
    if (token) {
        flb_sds_destroy(token);
    }
    /* Note: Don't free token_copy - librdkafka manages it */
}

/* Keep original function signature to match header file */
struct flb_aws_msk_iam *flb_aws_msk_iam_register_oauth_cb(struct flb_config *config,
                                                          rd_kafka_conf_t *kconf,
                                                          const char *cluster_arn,
                                                          void *owner)
{
    struct flb_aws_msk_iam *ctx;
    struct flb_msk_iam_cb *cb;
    char *region_str;

    flb_info("[msk_iam] registering OAuth callback with cluster ARN: %s", cluster_arn);

    if (!cluster_arn) {
        flb_error("[msk_iam] cluster ARN is required");
        return NULL;
    }

    ctx = flb_calloc(1, sizeof(struct flb_aws_msk_iam));
    if (!ctx) {
        flb_error("[msk_iam] failed to allocate context");
        return NULL;
    }

    ctx->cluster_arn = flb_sds_create(cluster_arn);
    if (!ctx->cluster_arn) {
        flb_error("[msk_iam] failed to create cluster ARN string");
        flb_free(ctx);
        return NULL;
    }

    /* Fix region extraction */
    region_str = extract_region(cluster_arn);
    if (!region_str || strlen(region_str) == 0) {
        flb_error("[msk_iam] failed to extract region from cluster ARN: %s", cluster_arn);
        flb_sds_destroy(ctx->cluster_arn);
        flb_free(ctx);
        if (region_str) flb_free(region_str);
        return NULL;
    }

    ctx->region = flb_sds_create(region_str);
    flb_free(region_str);

    if (!ctx->region) {
        flb_error("[msk_iam] failed to create region string");
        flb_sds_destroy(ctx->cluster_arn);
        flb_free(ctx);
        return NULL;
    }

    flb_info("[msk_iam] extracted region: %s", ctx->region);

    ctx->provider = flb_standard_chain_provider_create(config, NULL,
                                                       ctx->region, NULL, NULL,
                                                       flb_aws_client_generator(),
                                                       NULL);
    if (!ctx->provider) {
        flb_error("[msk_iam] failed to create AWS credentials provider");
        flb_aws_msk_iam_destroy(ctx);
        return NULL;
    }

    if (ctx->provider->provider_vtable->init(ctx->provider) != 0) {
        flb_error("[msk_iam] failed to initialize AWS credentials provider");
        flb_aws_msk_iam_destroy(ctx);
        return NULL;
    }

    cb = flb_calloc(1, sizeof(struct flb_msk_iam_cb));
    if (!cb) {
        flb_error("[msk_iam] failed to allocate callback context");
        flb_aws_msk_iam_destroy(ctx);
        return NULL;
    }
    cb->plugin_ctx = owner;
    cb->iam = ctx;

    /* Set the callback and opaque BEFORE any Kafka operations */
    rd_kafka_conf_set_oauthbearer_token_refresh_cb(kconf, oauthbearer_token_refresh_cb);
    rd_kafka_conf_set_opaque(kconf, cb);

    flb_info("[msk_iam] OAuth callback registered successfully");

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