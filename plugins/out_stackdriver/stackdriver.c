/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_oauth2.h>

#include <msgpack.h>

#include "stackdriver.h"
#include "stackdriver_conf.h"
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>

/*
 * Base64 Encoding in JWT must:
 *
 * - remove any trailing padding '=' character
 * - replace '+' with '-'
 * - replace '/' with '_'
 *
 * ref: https://www.rfc-editor.org/rfc/rfc7515.txt Appendix C
 */
int jwt_base64_url_encode(unsigned char *out_buf, size_t out_size,
                          unsigned char *in_buf, size_t in_size,
                          size_t *olen)

{
    int i;
    size_t len;

    /* do normal base64 encoding */
    mbedtls_base64_encode(out_buf, out_size - 1,
                          &len, in_buf, in_size);

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

static int jwt_encode(char *payload, char *secret,
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
    mbedtls_sha256_context sha256_ctx;
    mbedtls_rsa_context *rsa;
    flb_sds_t out;
    mbedtls_pk_context pk_ctx;
    unsigned char sig[256] = {0};

    buf_size = (strlen(payload) + strlen(secret)) * 2;
    buf = flb_malloc(buf_size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    /* Encode header */
    len = strlen(headers);
    mbedtls_base64_encode((unsigned char *) buf, buf_size - 1,
                          &olen, (unsigned char *) headers, len);

    /* Create buffer to store JWT */
    out = flb_sds_create_size(2048);
    if (!out) {
        flb_errno();
        flb_free(buf);
        return -1;
    }

    /* Append header */
    flb_sds_cat(out, buf, olen);
    flb_sds_cat(out, ".", 1);

    /* Encode Payload */
    len = strlen(payload);
    jwt_base64_url_encode((unsigned char *) buf, buf_size,
                          (unsigned char *) payload, len, &olen);

    /* Append Payload */
    flb_sds_cat(out, buf, olen);

    /* do sha256() of base64(header).base64(payload) */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char *) out,
                          flb_sds_len(out));
    mbedtls_sha256_finish(&sha256_ctx, sha256_buf);

    /* In mbedTLS cert length must include the null byte */
    len = strlen(secret) + 1;

    /* Load Private Key */
    mbedtls_pk_init(&pk_ctx);
    ret = mbedtls_pk_parse_key(&pk_ctx,
                               (unsigned char *) secret, len, NULL, 0);
    if (ret != 0) {
        flb_error("[out_stackdriver] error loading private key");
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    /* Create RSA context */
    rsa = mbedtls_pk_rsa(pk_ctx);
    if (!rsa) {
        flb_error("[out_stackdriver] error creating RSA context");
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    ret = mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL,
                                 MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                 0, (unsigned char *) sha256_buf, sig);
    if (ret != 0) {
        flb_error("[out_stackdriver] error signing SHA256");
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

    jwt_base64_url_encode((unsigned char *) sigd, 2048, sig, 256, &olen);

    flb_sds_cat(out, ".", 1);
    flb_sds_cat(out, sigd, olen);

    *out_signature = out;
    *out_size = flb_sds_len(out);

    flb_free(buf);
    flb_free(sigd);

    return 0;
}

static int get_google_token(struct flb_stackdriver *ctx)
{
    int ret;
    char *token;
    char *sig_data;
    size_t sig_size;
    time_t issued;
    time_t expires;
    char payload[1024];

    /* JWT encode for oauth2 */
    issued = time(NULL);
    expires = issued + FLB_STD_TOKEN_REFRESH;

    snprintf(payload, sizeof(payload) - 1,
             "{\"iss\": \"%s\", \"scope\": \"%s\", "
             "\"aud\": \"%s\", \"exp\": %lu, \"iat\": %lu}",
             ctx->client_email, FLB_STD_SCOPE,
             FLB_STD_AUTH_URL,
             expires, issued);

    /* Compose JWT signature */
    ret = jwt_encode(payload, ctx->private_key, &sig_data, &sig_size);
    if (ret != 0) {
        flb_error("[out_stackdriver] JWT signature generation failed");
        return -1;
    }

    flb_debug("[out_stackdriver] JWT signature:\n%s", sig_data);

    /* Get Authorization Token */
    ctx->o = flb_oauth2_create(ctx->config, FLB_STD_AUTH_URL, 3000);
    if (!ctx->o) {
        flb_sds_destroy(sig_data);
        flb_error("[out_stackdriver] cannot create oauth2 context");
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o,
                                    "grant_type", -1,
                                    "urn:ietf:params:oauth:"
                                    "grant-type:jwt-bearer", -1);
    if (ret == -1) {
        flb_error("[out_stackdriver] error appending oauth2 params");
        flb_sds_destroy(sig_data);
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o,
                                    "assertion", -1,
                                    sig_data, sig_size);
    if (ret == -1) {
        flb_error("[out_stackdriver] error appending oauth2 params");
        flb_sds_destroy(sig_data);
        return -1;
    }
    flb_sds_destroy(sig_data);

    /* Retrieve access token */
    token = flb_oauth2_token_get(ctx->o);
    if (!token) {
        flb_error("[out_stackdriver] error retrieving oauth2 access token");
        return -1;
    }

    return 0;
}

static int cb_stackdriver_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_stackdriver *ctx;

    /* Create config context */
    ctx = flb_stackdriver_conf_create(ins, config);
    if (!ctx) {
        flb_error("[out_stackdriver] configuration failed");
        return -1;
    }

    /* Set context */
    flb_output_set_context(ins, ctx);

    /* Create Upstream context for Stackdriver Logging (no oauth2 service) */
    ctx->u = flb_upstream_create_url(config, FLB_STD_AUTH_URL,
                                     FLB_IO_TLS, &ins->tls);
    if (!ctx->u) {
        flb_error("[out_stackdriver] upstream creation failed");
        return -1;
    }

    /* Retrieve oauth2 token */
    ret = get_google_token(ctx);
    if (ret == -1) {
        flb_warn("[out_stackdriver] token retrieval failed");
    }

    return 0;
}

static void cb_stackdriver_flush(void *data, size_t bytes,
                            char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    (void) i_ins;
    (void) config;
    char path[PATH_MAX];
    char time_formatted[255];
    size_t s;
    size_t off = 0;
    int len;
    int array_size = 0;
    struct flb_stackdriver *ctx = out_context;
    struct tm tm;
    struct flb_time tms;
    msgpack_object *obj;
    msgpack_object root;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /* Count number of records */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        array_size++;
    }
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    off = 0;
    msgpack_unpack_next(&result, data, bytes, &off);

    root = result.data;

    /* Get timestamp */
    flb_time_pop_from_msgpack(&tms, &result, &obj);

    msgpack_pack_map(&mp_pck, 3);

    /* jsonPayload */
    msgpack_pack_str(&mp_pck, 11);
    msgpack_pack_str_body(&mp_pck, "jsonPayload", 11);
    msgpack_pack_object(&mp_pck, *obj);

    /* logName */
    len = snprintf(path, sizeof(path) - 1,
                   "projects/%s/logs/%s", ctx->project_id, tag);

    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "logName", 7);
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, path, len);

    /* timestamp */
    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "timestamp", 9);

    /* Format the time */
    gmtime_r(&tms.tm.tv_sec, &tm);
    s = strftime(time_formatted, sizeof(time_formatted) - 1,
                 FLB_STD_TIME_FMT, &tm);
    len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                   ".%09" PRIu64 "Z", (uint64_t) tms.tm.tv_nsec);
    s += len;
    msgpack_pack_str(&mp_pck, s);
    msgpack_pack_str_body(&mp_pck, time_formatted, s);

    flb_pack_print(mp_sbuf.data, mp_sbuf.size);
    exit(1);
    FLB_OUTPUT_RETURN(FLB_RETRY);
}

static int cb_stackdriver_exit(void *data, struct flb_config *config)
{
    struct flb_stackdriver *ctx = data;

    if (!ctx) {
        return -1;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_stackdriver_conf_destroy(ctx);
    return 0;
}

struct flb_output_plugin out_stackdriver_plugin = {
    .name         = "stackdriver",
    .description  = "Send events to Google Stackdriver Logging",
    .cb_init      = cb_stackdriver_init,
    .cb_flush     = cb_stackdriver_flush,
    .cb_exit      = cb_stackdriver_exit,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
