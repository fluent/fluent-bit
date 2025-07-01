#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_hmac.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/aws/flb_aws_msk_iam.h>

#include <fluent-bit/flb_signv4.h>
#include <rdkafka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


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

static flb_sds_t build_msk_iam_payload(struct flb_aws_msk_iam *ctx,
                                       const char *host,
                                       time_t now)
{
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
    flb_sds_t payload = NULL;
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
    struct flb_aws_credentials *creds;

    /* Add validation */
    if (!ctx || !ctx->region || flb_sds_len(ctx->region) == 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: region is not set or invalid");
        return NULL;
    }

    if (!host || strlen(host) == 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: host is required");
        return NULL;
    }

    flb_info("[aws_msk_iam] build_msk_iam_payload: generating payload for host: %s, region: %s",
             host, ctx->region);

    creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
    if (!creds) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to get credentials");
        return NULL;
    }

    if (!creds->access_key_id || !creds->secret_access_key) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: incomplete credentials");
        flb_aws_credentials_destroy(creds);
        return NULL;
    }

    flb_info("[aws_msk_iam] build_msk_iam_payload: using access key: %.10s...", creds->access_key_id);

    gmtime_r(&now, &gm);
    strftime(amzdate, sizeof(amzdate) - 1, "%Y%m%dT%H%M%SZ", &gm);
    strftime(datestamp, sizeof(datestamp) - 1, "%Y%m%d", &gm);

    flb_info("[aws_msk_iam] build_msk_iam_payload: timestamp: %s, date: %s", amzdate, datestamp);

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

    credential_enc = uri_encode_params(credential, flb_sds_len(credential));
    if (!credential_enc) {
        goto error;
    }

    /* CRITICAL: Encode the action parameter */
    action_enc = uri_encode_params("kafka-cluster:Connect", 21);
    if (!action_enc) {
        goto error;
    }

    /* Build canonical query string with ACTION parameter first (alphabetical order) */
    query = flb_sds_create_size(8192);
    if (!query) {
        goto error;
    }

    /* note: Action must be FIRST in alphabetical order */
    query = flb_sds_printf(&query,
                           "Action=%s&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s"
                           "&X-Amz-Date=%s&X-Amz-Expires=900",
                           action_enc, credential_enc, amzdate);
    if (!query) {
        goto error;
    }

    /* Add session token if present (before SignedHeaders alphabetically) */
    if (creds->session_token && flb_sds_len(creds->session_token) > 0) {
        flb_info("[aws_msk_iam] build_msk_iam_payload: adding session token (length: %zu)",
                 flb_sds_len(creds->session_token));

        session_token_enc = uri_encode_params(creds->session_token,
                                              flb_sds_len(creds->session_token));
        if (!session_token_enc) {
            flb_error("[aws_msk_iam] build_msk_iam_payload: failed to encode session token");
            goto error;
        }

        tmp = flb_sds_printf(&query, "&X-Amz-Security-Token=%s", session_token_enc);
        if (!tmp) {
            flb_error("[aws_msk_iam] build_msk_iam_payload: failed to append session token to query");
            goto error;
        }
        query = tmp;
    }

    /* Add SignedHeaders LAST (alphabetically after Security-Token) */
    tmp = flb_sds_printf(&query, "&X-Amz-SignedHeaders=host");
    if (!tmp) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to append SignedHeaders");
        goto error;
    }
    query = tmp;

    /* Build canonical request */
    canonical = flb_sds_create_size(16384);
    if (!canonical) {
        goto error;
    }

    /* CRITICAL: MSK IAM canonical request format - use SHA256 of empty string, not UNSIGNED-PAYLOAD */
    if (flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) "", 0, empty_payload_hash,
                        sizeof(empty_payload_hash)) != FLB_CRYPTO_SUCCESS) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to hash empty payload");
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
    if (!canonical) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to build canonical request");
        goto error;
    }

    /* Hash canonical request immediately */
    if (flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) canonical,
                        flb_sds_len(canonical), sha256_buf,
                        sizeof(sha256_buf)) != FLB_CRYPTO_SUCCESS) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to hash canonical request");
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
                                    amzdate, datestamp, ctx->region, hexhash);
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
    if (hmac_sha256_sign(key_date, (unsigned char *) key, flb_sds_len(key), (unsigned char *) datestamp, len) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to sign date");
        flb_sds_destroy(key);
        goto error;
    }
    flb_sds_destroy(key);

    len = strlen(ctx->region);
    if (hmac_sha256_sign(key_region, key_date, 32, (unsigned char *) ctx->region, len) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to sign region");
        goto error;
    }

    if (hmac_sha256_sign(key_service, key_region, 32, (unsigned char *) "kafka-cluster", 13) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to sign service");
        goto error;
    }

    if (hmac_sha256_sign(key_signing, key_service, 32,
                        (unsigned char *) "aws4_request", 12) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to create signing key");
        goto error;
    }

    if (hmac_sha256_sign(sig, key_signing, 32,
                         (unsigned char *) string_to_sign, flb_sds_len(string_to_sign)) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to sign request");
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

    /* Build the complete presigned URL */
    presigned_url = flb_sds_create_size(16384);
    if (!presigned_url) {
        goto error;
    }

    presigned_url = flb_sds_printf(&presigned_url, "https://%s/?%s", host, query);
    if (!presigned_url) {
        goto error;
    }

    /* Base64 URL encode the presigned URL (RawURLEncoding - no padding like Go) */
    url_len = flb_sds_len(presigned_url);
    encoded_len = ((url_len + 2) / 3) * 4 + 1; /* Base64 encoding size + null terminator */

    /* Allocate one extra byte for null terminator */
    payload = flb_sds_create_size(encoded_len + 1);
    if (!payload) {
        goto error;
    }

    encode_result = flb_base64_encode((unsigned char*) payload, encoded_len, &actual_encoded_len,
                                      (const unsigned char *) presigned_url, url_len);
    if (encode_result == -1) {
        flb_error("[aws_msk_iam] build_msk_iam_payload: failed to base64 encode URL");
        goto error;
    }

    /* Update the SDS length to match actual encoded length */
    flb_sds_len_set(payload, actual_encoded_len);
    /* Always null-terminate within bounds */
    payload[actual_encoded_len] = '\0';

    /* Convert to Base64 URL encoding AND remove padding (RawURLEncoding like Go) */
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

    /* Remove ALL padding (RawURLEncoding) */
    final_len = flb_sds_len(payload);
    while (final_len > 0 && payload[final_len-1] == '=') {
        final_len--;
    }
    flb_sds_len_set(payload, final_len);
    /* Always null-terminate within bounds */
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
    flb_aws_credentials_destroy(creds);
    return payload;

error:
    flb_error("[aws_msk_iam] build_msk_iam_payload: error occurred during payload generation");
    flb_sds_destroy(credential);
    flb_sds_destroy(credential_enc);
    flb_sds_destroy(canonical);
    flb_sds_destroy(hexhash);
    flb_sds_destroy(string_to_sign);
    flb_sds_destroy(hexsig);
    flb_sds_destroy(query);
    flb_sds_destroy(action_enc);
    flb_sds_destroy(payload);
    flb_sds_destroy(presigned_url);

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
    struct flb_aws_msk_iam *ctx;
    struct flb_aws_credentials *creds = NULL;
    flb_sds_t payload = NULL;
    char *payload_copy = NULL;
    char host[256];
    rd_kafka_resp_err_t err;
    char errstr[512];
    int64_t now;
    int64_t md_lifetime_ms;
    const char *s3_suffix = "-s3";
    size_t arn_len;
    size_t suffix_len;
    (void) oauthbearer_config;

    flb_debug("[aws_msk_iam] running OAuth bearer token refresh callback");

    ctx = opaque;
    if (!ctx->region || flb_sds_len(ctx->region) == 0) {
        flb_error("[aws_msk_iam] region is not set or invalid");
        rd_kafka_oauthbearer_set_token_failure(rk, "region not set");
        return;
    }

    if (ctx->cluster_arn) {
        arn_len = strlen(ctx->cluster_arn);
        suffix_len = strlen(s3_suffix);
        if (arn_len >= suffix_len && strcmp(ctx->cluster_arn + arn_len - suffix_len, s3_suffix) == 0) {
            /* MSK Serverless cluster - use generic serverless endpoint */
            snprintf(host, sizeof(host), "kafka-serverless.%s.amazonaws.com", ctx->region);
            flb_info("[aws_msk_iam] MSK Serverless cluster, using generic endpoint: %s", host);
        }
        else {
            /* Regular MSK cluster - use generic endpoint */
            snprintf(host, sizeof(host), "kafka.%s.amazonaws.com", ctx->region);
            flb_info("[aws_msk_iam] Regular MSK cluster, using generic endpoint: %s", host);
        }
    }
    else {
        /* Regular MSK cluster - use generic endpoint */
        snprintf(host, sizeof(host), "kafka.%s.amazonaws.com", ctx->region);
        flb_info("[aws_msk_iam] Regular MSK cluster, using generic endpoint: %s", host);
    }

    flb_info("[aws_msk_iam] requesting MSK IAM payload for region: %s, host: %s", ctx->region, host);

    payload = build_msk_iam_payload(ctx, host, time(NULL));
    if (!payload) {
        flb_error("[aws_msk_iam] failed to generate MSK IAM payload");
        rd_kafka_oauthbearer_set_token_failure(rk, "payload generation failed");
        return;
    }

    /* aws provider credentials */
    creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
    if (creds && creds->access_key_id) {
        printf("[aws_msk_iam] PRINCIPAL: %s\n", creds->access_key_id);
    }

    payload_copy = strdup(payload);
    if (!payload_copy) {
        flb_error("[aws_msk_iam] failed to duplicate payload string");
        rd_kafka_oauthbearer_set_token_failure(rk, "memory allocation failed");
        goto cleanup;
    }

    if (!creds) {
        creds = ctx->provider->provider_vtable->get_credentials(ctx->provider);
    }

    if (!creds || !creds->access_key_id) {
        flb_error("[aws_msk_iam] failed to retrieve AWS credentials for principal");
        rd_kafka_oauthbearer_set_token_failure(rk, "credential retrieval failed");
        goto cleanup;
    }


    now = time(NULL);
    md_lifetime_ms = (now + 900) * 1000;

    err = rd_kafka_oauthbearer_set_token(
                                         rk,
                                         payload_copy,
                                         md_lifetime_ms,
                                         creds->access_key_id,
                                         NULL,
                                         0,
                                         errstr,
                                         sizeof(errstr)
                                        );

    if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
        flb_error("[aws_msk_iam] failed to set OAuth bearer token: %s", errstr);
        rd_kafka_oauthbearer_set_token_failure(rk, errstr);
    }
    else {
        flb_info("[aws_msk_iam] OAuth bearer token successfully set");
    }

cleanup:
    if (creds) {
        flb_aws_credentials_destroy(creds);
    }
    if (payload) {
        flb_sds_destroy(payload);
    }

    /* note: don't free payload_copy - librdkafka manages it */
}

/* Keep original function signature to match header file */
struct flb_aws_msk_iam *flb_aws_msk_iam_register_oauth_cb(struct flb_config *config,
                                                          rd_kafka_conf_t *kconf,
                                                          const char *cluster_arn,
                                                          void *owner)
{
    struct flb_aws_msk_iam *ctx;
    char *region_str;

    flb_info("[aws_msk_iam] registering OAuth callback with cluster ARN: %s", cluster_arn);

    if (!cluster_arn) {
        flb_error("[aws_msk_iam] cluster ARN is required");
        return NULL;
    }

    ctx = flb_calloc(1, sizeof(struct flb_aws_msk_iam));
    if (!ctx) {
        flb_error("[aws_msk_iam] failed to allocate context");
        return NULL;
    }

    ctx->cluster_arn = flb_sds_create(cluster_arn);
    if (!ctx->cluster_arn) {
        flb_error("[aws_msk_iam] failed to create cluster ARN string");
        flb_free(ctx);
        return NULL;
    }

    /* Fix region extraction */
    region_str = extract_region(cluster_arn);
    if (!region_str || strlen(region_str) == 0) {
        flb_error("[aws_msk_iam] failed to extract region from cluster ARN: %s", cluster_arn);
        flb_sds_destroy(ctx->cluster_arn);
        flb_free(ctx);
        if (region_str) flb_free(region_str);
        return NULL;
    }

    ctx->region = flb_sds_create(region_str);
    flb_free(region_str);

    if (!ctx->region) {
        flb_error("[aws_msk_iam] failed to create region string");
        flb_sds_destroy(ctx->cluster_arn);
        flb_free(ctx);
        return NULL;
    }

    flb_info("[aws_msk_iam] extracted region: %s", ctx->region);

    ctx->provider = flb_standard_chain_provider_create(config, NULL,
                                                       ctx->region, NULL, NULL,
                                                       flb_aws_client_generator(),
                                                       NULL);
    if (!ctx->provider) {
        flb_error("[aws_msk_iam] failed to create AWS credentials provider");
        flb_aws_msk_iam_destroy(ctx);
        return NULL;
    }

    if (ctx->provider->provider_vtable->init(ctx->provider) != 0) {
        flb_error("[aws_msk_iam] failed to initialize AWS credentials provider");
        flb_aws_msk_iam_destroy(ctx);
        return NULL;
    }

    /* Set the callback and opaque BEFORE any Kafka operations */
    rd_kafka_conf_set_oauthbearer_token_refresh_cb(kconf, oauthbearer_token_refresh_cb);
    rd_kafka_conf_set_opaque(kconf, ctx);

    flb_info("[aws_msk_iam] OAuth callback registered successfully");

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
