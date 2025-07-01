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

#include <fluent-bit/flb_signv4.h>
#include <rdkafka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Lightweight config - NO persistent AWS provider */
struct flb_aws_msk_iam {
    struct flb_config *flb_config;  /* For creating AWS provider on-demand */
    flb_sds_t region;
    flb_sds_t cluster_arn;
};

/* Utility functions - same as before */
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

/* Stateless payload generator - creates AWS provider on demand */
static flb_sds_t build_msk_iam_payload_stateless(struct flb_aws_msk_iam *config,
                                                 const char *host,
                                                 time_t now)
{
    struct flb_aws_provider *temp_provider = NULL;
    struct flb_aws_credentials *creds = NULL;
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

    /* Validate inputs */
    if (!config || !config->region || flb_sds_len(config->region) == 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: region is not set or invalid");
        return NULL;
    }

    if (!host || strlen(host) == 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: host is required");
        return NULL;
    }

    flb_info("[aws_msk_iam] build_msk_iam_payload_stateless: generating payload for host: %s, region: %s",
             host, config->region);

    /* Create AWS provider on-demand */
    temp_provider = flb_standard_chain_provider_create(config->flb_config, NULL,
                                                      config->region, NULL, NULL,
                                                      flb_aws_client_generator(),
                                                      NULL);
    if (!temp_provider) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to create AWS credentials provider");
        return NULL;
    }

    if (temp_provider->provider_vtable->init(temp_provider) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to initialize AWS credentials provider");
        temp_provider->provider_vtable->destroy(temp_provider);
        return NULL;
    }

    /* Get credentials */
    creds = temp_provider->provider_vtable->get_credentials(temp_provider);
    if (!creds) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to get credentials");
        temp_provider->provider_vtable->destroy(temp_provider);
        return NULL;
    }

    if (!creds->access_key_id || !creds->secret_access_key) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: incomplete credentials");
        flb_aws_credentials_destroy(creds);
        temp_provider->provider_vtable->destroy(temp_provider);
        return NULL;
    }

    flb_info("[aws_msk_iam] build_msk_iam_payload_stateless: using access key: %.10s...", creds->access_key_id);

    gmtime_r(&now, &gm);
    strftime(amzdate, sizeof(amzdate) - 1, "%Y%m%dT%H%M%SZ", &gm);
    strftime(datestamp, sizeof(datestamp) - 1, "%Y%m%d", &gm);

    flb_info("[aws_msk_iam] build_msk_iam_payload_stateless: timestamp: %s, date: %s", amzdate, datestamp);

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
        flb_info("[aws_msk_iam] build_msk_iam_payload_stateless: adding session token (length: %zu)",
                 flb_sds_len(creds->session_token));

        session_token_enc = uri_encode_params(creds->session_token,
                                             flb_sds_len(creds->session_token));
        if (!session_token_enc) {
            flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to encode session token");
            goto error;
        }

        tmp = flb_sds_printf(&query, "&X-Amz-Security-Token=%s", session_token_enc);
        if (!tmp) {
            flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to append session token to query");
            goto error;
        }
        query = tmp;
    }

    /* Add SignedHeaders LAST (alphabetically after Security-Token) */
    tmp = flb_sds_printf(&query, "&X-Amz-SignedHeaders=host");
    if (!tmp) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to append SignedHeaders");
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
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to hash empty payload");
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
    empty_payload_hex = NULL;  /* Prevent double-free */
    if (!canonical) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to build canonical request");
        goto error;
    }

    /* Hash canonical request immediately */
    if (flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) canonical,
                       flb_sds_len(canonical), sha256_buf,
                       sizeof(sha256_buf)) != FLB_CRYPTO_SUCCESS) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to hash canonical request");
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
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to sign date");
        goto error;
    }

    /* Clean up key immediately after use - prevent double-free */
    flb_sds_destroy(key);
    key = NULL;

    len = strlen(config->region);
    if (hmac_sha256_sign(key_region, key_date, 32, (unsigned char *) config->region, len) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to sign region");
        goto error;
    }

    if (hmac_sha256_sign(key_service, key_region, 32, (unsigned char *) "kafka-cluster", 13) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to sign service");
        goto error;
    }

    if (hmac_sha256_sign(key_signing, key_service, 32,
                        (unsigned char *) "aws4_request", 12) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to create signing key");
        goto error;
    }

    if (hmac_sha256_sign(sig, key_signing, 32,
                        (unsigned char *) string_to_sign, flb_sds_len(string_to_sign)) != 0) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to sign request");
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

    /* Base64 URL encode the presigned URL */
    url_len = flb_sds_len(presigned_url);
    encoded_len = ((url_len + 2) / 3) * 4 + 1; /* Base64 encoding size + null terminator */

    payload = flb_sds_create_size(encoded_len);
    if (!payload) {
        goto error;
    }

    encode_result = flb_base64_encode((unsigned char*) payload, encoded_len, &actual_encoded_len,
                                     (const unsigned char*) presigned_url, url_len);
    if (encode_result == -1) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to base64 encode URL");
        goto error;
    }
    flb_sds_len_set(payload, actual_encoded_len);

    /* Convert to Base64 URL encoding (replace + with -, / with _, remove padding =) */
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

    /* Remove padding */
    len = flb_sds_len(payload);
    while (len > 0 && payload[len-1] == '=') {
        len--;
    }
    flb_sds_len_set(payload, len);
    payload[len] = '\0';

    /* Build the complete presigned URL */
    flb_sds_destroy(presigned_url);
    presigned_url = flb_sds_create_size(16384);
    if (!presigned_url) {
        goto error;
    }

    presigned_url = flb_sds_printf(&presigned_url, "https://%s/?%s", host, query);
    if (!presigned_url) {
        goto error;
    }

    /* Add User-Agent parameter to the signed URL (like Go implementation) */
    tmp = flb_sds_printf(&presigned_url, "&User-Agent=fluent-bit-msk-iam");
    if (!tmp) {
        goto error;
    }
    presigned_url = tmp;

    /* Base64 URL encode the presigned URL (RawURLEncoding - no padding like Go) */
    url_len = flb_sds_len(presigned_url);
    encoded_len = ((url_len + 2) / 3) * 4 + 1; /* Base64 encoding size + null terminator */

    flb_sds_destroy(payload);
    payload = flb_sds_create_size(encoded_len);
    if (!payload) {
        goto error;
    }

    encode_result = flb_base64_encode((unsigned char*) payload, encoded_len, &actual_encoded_len,
                                     (const unsigned char *) presigned_url, url_len);
    if (encode_result == -1) {
        flb_error("[aws_msk_iam] build_msk_iam_payload_stateless: failed to base64 encode URL");
        goto error;
    }

    /* Update the SDS length to match actual encoded length */
    flb_sds_len_set(payload, actual_encoded_len);

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
    payload[final_len] = '\0';

    /* Clean up before successful return */
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
    if (creds) {
        flb_aws_credentials_destroy(creds);
    }
    if (temp_provider) {
        temp_provider->provider_vtable->destroy(temp_provider);
    }

    return payload;

error:
    /* Clean up everything - check for NULL to prevent double-free */
    if (credential) {
        flb_sds_destroy(credential);
    }
    if (credential_enc) {
        flb_sds_destroy(credential_enc);
    }
    if (canonical) {
        flb_sds_destroy(canonical);
    }
    if (hexhash) {
        flb_sds_destroy(hexhash);
    }
    if (string_to_sign) {
        flb_sds_destroy(string_to_sign);
    }
    if (hexsig) {
        flb_sds_destroy(hexsig);
    }
    if (query) {
        flb_sds_destroy(query);
    }
    if (action_enc) {
        flb_sds_destroy(action_enc);
    }
    if (presigned_url) {
        flb_sds_destroy(presigned_url);
    }
    if (key) {  /* Only destroy if not already destroyed */
        flb_sds_destroy(key);
    }
    if (payload) {
        flb_sds_destroy(payload);
    }
    if (session_token_enc) {
        flb_sds_destroy(session_token_enc);
    }
    if (creds) {
        flb_aws_credentials_destroy(creds);
    }
    if (temp_provider) {
        temp_provider->provider_vtable->destroy(temp_provider);
    }

    return NULL;
}


/* Stateless callback - creates AWS provider on-demand for each refresh */
static void oauthbearer_token_refresh_cb(rd_kafka_t *rk,
                                         const char *oauthbearer_config,
                                         void *opaque)
{
    char host[256];
    flb_sds_t payload = NULL;
    rd_kafka_resp_err_t err;
    char errstr[512];
    int64_t now;
    int64_t md_lifetime_ms;
    const char *s3_suffix = "-s3";
    size_t arn_len;
    size_t suffix_len;
    struct flb_aws_msk_iam *config;
    struct flb_aws_credentials *creds = NULL;
    struct flb_kafka_opaque *kafka_opaque;
    struct flb_aws_provider *temp_provider = NULL;
    (void) oauthbearer_config;

    kafka_opaque = (struct flb_kafka_opaque *) opaque;
    if (!kafka_opaque || !kafka_opaque->msk_iam_ctx) {
        flb_error("[aws_msk_iam] oauthbearer_token_refresh_cb: invalid opaque context");
        rd_kafka_oauthbearer_set_token_failure(rk, "invalid context");
        return;
    }

    flb_debug("[aws_msk_iam] running OAuth bearer token refresh callback");

    /* get the msk_iam config (not persistent context!) */
    config = kafka_opaque->msk_iam_ctx;

    /* validate region (mandatory) */
    if (!config->region || flb_sds_len(config->region) == 0) {
        flb_error("[aws_msk_iam] region is not set or invalid");
        rd_kafka_oauthbearer_set_token_failure(rk, "region not set");
        return;
    }

    /* Determine host endpoint */
    if (config->cluster_arn) {
        arn_len = strlen(config->cluster_arn);
        suffix_len = strlen(s3_suffix);
        if (arn_len >= suffix_len && strcmp(config->cluster_arn + arn_len - suffix_len, s3_suffix) == 0) {
            snprintf(host, sizeof(host), "kafka-serverless.%s.amazonaws.com", config->region);
            flb_info("[aws_msk_iam] MSK Serverless cluster, using generic endpoint: %s", host);
        }
        else {
            snprintf(host, sizeof(host), "kafka.%s.amazonaws.com", config->region);
            flb_info("[aws_msk_iam] Regular MSK cluster, using generic endpoint: %s", host);
        }
    }
    else {
        snprintf(host, sizeof(host), "kafka.%s.amazonaws.com", config->region);
        flb_info("[aws_msk_iam] Regular MSK cluster, using generic endpoint: %s", host);
    }

    flb_info("[aws_msk_iam] requesting MSK IAM payload for region: %s, host: %s", config->region, host);

    /* Generate payload using stateless function - creates and destroys AWS provider internally */
    payload = build_msk_iam_payload_stateless(config, host, time(NULL));
    if (!payload) {
        flb_error("[aws_msk_iam] failed to generate MSK IAM payload");
        rd_kafka_oauthbearer_set_token_failure(rk, "payload generation failed");
        return;
    }

    /* Get credentials for principal (create temporary provider just for this) */
    temp_provider = flb_standard_chain_provider_create(config->flb_config, NULL,
                                                      config->region, NULL, NULL,
                                                      flb_aws_client_generator(),
                                                      NULL);
    if (temp_provider) {
        if (temp_provider->provider_vtable->init(temp_provider) == 0) {
            creds = temp_provider->provider_vtable->get_credentials(temp_provider);
        }
    }

    now = time(NULL);
    md_lifetime_ms = (now + 900) * 1000;

    err = rd_kafka_oauthbearer_set_token(rk,
                                        payload,
                                        md_lifetime_ms,
                                        creds ? creds->access_key_id : "unknown",
                                        NULL,
                                        0,
                                        errstr,
                                        sizeof(errstr));

    if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
        flb_error("[aws_msk_iam] failed to set OAuth bearer token: %s", errstr);
        rd_kafka_oauthbearer_set_token_failure(rk, errstr);
    }
    else {
        flb_info("[aws_msk_iam] OAuth bearer token successfully set");
    }

    /* Clean up everything immediately - no memory leaks possible! */
    if (creds) {
        flb_aws_credentials_destroy(creds);
    }
    if (temp_provider) {
        temp_provider->provider_vtable->destroy(temp_provider);
    }
    if (payload) {
        flb_sds_destroy(payload);
    }
}

/* Register callback with lightweight config - keeps your current interface */
struct flb_aws_msk_iam *flb_aws_msk_iam_register_oauth_cb(struct flb_config *config,
                                                          rd_kafka_conf_t *kconf,
                                                          const char *cluster_arn,
                                                          struct flb_kafka_opaque *opaque)
{
    struct flb_aws_msk_iam *ctx;
    char *region_str;

    flb_info("[aws_msk_iam] registering OAuth callback with cluster ARN: %s", cluster_arn);

    if (!cluster_arn) {
        flb_error("[aws_msk_iam] cluster ARN is required");
        return NULL;
    }

    /* Allocate lightweight config - NO AWS provider! */
    ctx = flb_calloc(1, sizeof(struct flb_aws_msk_iam));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Store the flb_config for on-demand provider creation */
    ctx->flb_config = config;

    ctx->cluster_arn = flb_sds_create(cluster_arn);
    if (!ctx->cluster_arn) {
        flb_error("[aws_msk_iam] failed to create cluster ARN string");
        flb_free(ctx);
        return NULL;
    }

    /* Extract region */
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

    /* NO persistent AWS provider creation! */
    flb_info("[aws_msk_iam] using stateless AWS provider approach");

    /* Set the callback and opaque */
    rd_kafka_conf_set_oauthbearer_token_refresh_cb(kconf, oauthbearer_token_refresh_cb);
    flb_kafka_opaque_set(opaque, NULL, ctx);
    rd_kafka_conf_set_opaque(kconf, opaque);

    flb_info("[aws_msk_iam] OAuth callback registered successfully (stateless)");

    return ctx;
}

/* Simple destroy - just config cleanup, no AWS provider to leak! */
void flb_aws_msk_iam_destroy(struct flb_aws_msk_iam *ctx)
{
    if (!ctx) {
        return;
    }

    flb_info("[aws_msk_iam] destroying stateless MSK IAM config");

    /* NO AWS provider to destroy! */
    if (ctx->region) {
        flb_sds_destroy(ctx->region);
    }
    if (ctx->cluster_arn) {
        flb_sds_destroy(ctx->cluster_arn);
    }
    flb_free(ctx);
}
