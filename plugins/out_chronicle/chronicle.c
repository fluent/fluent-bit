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
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include <msgpack.h>

#include "chronicle.h"
#include "chronicle_conf.h"

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
int chronicle_jwt_base64_url_encode(unsigned char *out_buf, size_t out_size,
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

static int chronicle_jwt_encode(struct flb_chronicle *ctx,
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
    flb_sds_cat_safe(&out, buf, olen);
    flb_sds_cat_safe(&out, ".", 1);

    /* Encode Payload */
    len = strlen(payload);
    chronicle_jwt_base64_url_encode((unsigned char *) buf, buf_size,
                                    (unsigned char *) payload, len, &olen);

    /* Append Payload */
    flb_sds_cat_safe(&out, buf, olen);

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

    len = strlen(secret);
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

    chronicle_jwt_base64_url_encode((unsigned char *) sigd, 2048, sig, 256, &olen);

    flb_sds_cat_safe(&out, ".", 1);
    flb_sds_cat_safe(&out, sigd, olen);

    *out_signature = out;
    *out_size = flb_sds_len(out);

    flb_free(buf);
    flb_free(sigd);

    return 0;
}

/* Create a new oauth2 context and get a oauth2 token */
static int chronicle_get_oauth2_token(struct flb_chronicle *ctx)
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
    expires = issued + FLB_CHRONICLE_TOKEN_REFRESH;

    snprintf(payload, sizeof(payload) - 1,
             "{\"iss\": \"%s\", \"scope\": \"%s\", "
             "\"aud\": \"%s\", \"exp\": %lu, \"iat\": %lu}",
             ctx->oauth_credentials->client_email, FLB_CHRONICLE_SCOPE,
             FLB_CHRONICLE_AUTH_URL,
             expires, issued);

    /* Compose JWT signature */
    ret = chronicle_jwt_encode(ctx, payload, ctx->oauth_credentials->private_key,
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

static flb_sds_t get_google_token(struct flb_chronicle *ctx)
{
    int ret = 0;
    flb_sds_t output = NULL;

    if (pthread_mutex_lock(&ctx->token_mutex)){
        flb_plg_error(ctx->ins, "error locking mutex");
        return NULL;
    }

    if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
        ret = chronicle_get_oauth2_token(ctx);
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

static int validate_log_type(struct flb_chronicle *ctx, struct flb_config *config,
                             const char *body, size_t len)
{
    int ret = -1;
    int root_type;
    char *msgpack_buf = NULL;
    size_t msgpack_size;
    size_t off = 0;
    msgpack_unpacked result;
    int i, j, k;
    msgpack_object key;
    msgpack_object val;
    msgpack_object root;
    msgpack_object *array;
    msgpack_object *supported_type;
    int root_map_size;
    int array_size = 0;


    ret = flb_pack_json(body, len,
                        &msgpack_buf, &msgpack_size,
                        &root_type, NULL);

    if (ret != 0 || root_type != JSMN_OBJECT) {
        flb_plg_error(ctx->ins, "json to msgpack conversion error");
    }

    ret = -1;
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, msgpack_buf, msgpack_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "Invalid log_type payload");
            ret = -2;

            goto cleanup;
        }

        root = result.data;
        root_map_size = root.via.map.size;

        for (i = 0; i < root_map_size; i++) {
            key = root.via.map.ptr[i].key;
            val = root.via.map.ptr[i].val;

            if (val.type != MSGPACK_OBJECT_ARRAY) {
                flb_plg_error(ctx->ins, "Invalid inner array type of log_type payload");
                ret = -2;

                goto cleanup;
            }

            array = val.via.array.ptr;
            array_size = val.via.array.size;

            for (j = 0; j < array_size; j++) {
                supported_type = &array[j];

                if (supported_type->type != MSGPACK_OBJECT_MAP) {
                    flb_plg_error(ctx->ins, "Invalid inner maps of log_type payload");
                    ret = -2;

                    continue;
                }

                for (k = 0; k < supported_type->via.map.size; k++) {
                    key = supported_type->via.map.ptr[k].key;
                    val = supported_type->via.map.ptr[k].val;

                    if (strncmp("logType", key.via.str.ptr, key.via.str.size) == 0) {
                        if (strncmp(ctx->log_type, val.via.bin.ptr, val.via.str.size) == 0) {
                            ret = 0;
                            goto cleanup;
                        }
                    }
                }
            }
        }
    }

cleanup:
    msgpack_unpacked_destroy(&result);

    /* release 'out_buf' if it was allocated */
    if (msgpack_buf) {
        flb_free(msgpack_buf);
    }

    return ret;
}

static int check_chronicle_log_type(struct flb_chronicle *ctx, struct flb_config *config)
{
    int ret;
    size_t b_sent;
    flb_sds_t token;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        return -1;
    }

    /* Get or renew Token */
    token = get_google_token(ctx);

    if (!token) {
        flb_plg_error(ctx->ins, "cannot retrieve oauth2 token");
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_GET, FLB_CHRONICLE_LOG_TYPE_ENDPOINT,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(token);

        return -1;
    }

    /* Chronicle supported types are growing. Not to specify the read limit. */
    flb_http_buffer_size(c, 0);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);

    /* Compose and append Authorization header */
    flb_http_add_header(c, "Authorization", 13, token, flb_sds_len(token));

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* validate response */
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        goto cleanup;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_plg_debug(ctx->ins, "HTTP Status=%i", c->resp.status);
        if (c->resp.status == 200) {
            ret = validate_log_type(ctx, config, c->resp.payload, c->resp.payload_size);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "Validate log_type is failed");
                goto cleanup;
            }
        }
        else {
            if (c->resp.payload && c->resp.payload_size > 0) {
                /* we got an error */
                flb_plg_warn(ctx->ins, "response\n%s", c->resp.payload);
            }

            goto cleanup;
        }
    }

cleanup:

    /* Cleanup */
    flb_sds_destroy(token);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return ret;
}

static int cb_chronicle_init(struct flb_output_instance *ins,
                             struct flb_config *config, void *data)
{
    char *token;
    int io_flags = FLB_IO_TLS;
    struct flb_chronicle *ctx;
    int ret;

    /* Create config context */
    ctx = flb_chronicle_conf_create(ins, config);
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
     * Create upstream context for Chronicle Streaming Inserts
     * (no oauth2 service)
     */
    ctx->u = flb_upstream_create_url(config, ctx->uri,
                                     io_flags, ins->tls);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "upstream creation failed");
        return -1;
    }

    /* Create oauth2 context */
    ctx->o = flb_oauth2_create(ctx->config, FLB_CHRONICLE_AUTH_URL, 3000);
    if (!ctx->o) {
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        return -1;
    }
    flb_output_upstream_set(ctx->u, ins);

    /* Get or renew the OAuth2 token */
    token = get_google_token(ctx);

    if (!token) {
        flb_plg_warn(ctx->ins, "token retrieval failed");
    }
    else {
        flb_sds_destroy(token);
    }

    ret = check_chronicle_log_type(ctx, config);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "Validate log_type failed. '%s' is not supported. ret = %d",
                      ctx->log_type, ret);
        return -1;
    }

    return 0;
}

static flb_sds_t flb_pack_msgpack_extract_log_key(void *out_context, uint64_t bytes, struct flb_log_event log_event)
{
    int i;
    int map_size;
    int check = FLB_FALSE;
    int log_key_found = FLB_FALSE;
    int ret;
    struct flb_chronicle *ctx = out_context;
    char *val_buf;
    char *key_str = NULL;
    size_t key_str_size = 0;
    size_t msgpack_size = bytes + bytes / 4;
    size_t val_offset = 0;
    flb_sds_t out_buf;
    msgpack_object map;
    msgpack_object key;
    msgpack_object val;

    /* Allocate buffer to store log_key contents */
    val_buf = flb_calloc(1, msgpack_size);
    if (val_buf == NULL) {
        flb_plg_error(ctx->ins, "Could not allocate enough "
                      "memory to read record");
        flb_errno();
        return NULL;
    }

    /* Get the record/map */
    map = *log_event.body;

    if (map.type != MSGPACK_OBJECT_MAP) {
        flb_free(val_buf);
        return NULL;
    }

    map_size = map.via.map.size;

    /* Extract log_key from record and append to output buffer */
    for (i = 0; i < map_size; i++) {
        key = map.via.map.ptr[i].key;
        val = map.via.map.ptr[i].val;

        if (key.type == MSGPACK_OBJECT_BIN) {
            key_str  = (char *) key.via.bin.ptr;
            key_str_size = key.via.bin.size;
            check = FLB_TRUE;
        }
        if (key.type == MSGPACK_OBJECT_STR) {
            key_str  = (char *) key.via.str.ptr;
            key_str_size = key.via.str.size;
            check = FLB_TRUE;
        }

        if (check == FLB_TRUE) {
            if (strncmp(ctx->log_key, key_str, key_str_size) == 0) {
                log_key_found = FLB_TRUE;

                /*
                 * Copy contents of value into buffer. Necessary to copy
                 * strings because flb_msgpack_to_json does not handle nested
                 * JSON gracefully and double escapes them.
                 */
                if (val.type == MSGPACK_OBJECT_BIN) {
                    memcpy(val_buf + val_offset, val.via.bin.ptr, val.via.bin.size);
                    val_offset += val.via.bin.size;
                    val_buf[val_offset] = '\0';
                    val_offset++;
                }
                else if (val.type == MSGPACK_OBJECT_STR) {
                    memcpy(val_buf + val_offset, val.via.str.ptr, val.via.str.size);
                    val_offset += val.via.str.size;
                    val_buf[val_offset] = '\0';
                    val_offset++;
                }
                else {
                    ret = flb_msgpack_to_json(val_buf + val_offset,
                                              msgpack_size - val_offset, &val);
                    if (ret < 0) {
                        break;
                    }
                    val_offset += ret;
                    val_buf[val_offset] = '\0';
                    val_offset++;
                }
                /* Exit early once log_key has been found for current record */
                break;
            }
        }
    }

    /* Check the flag *after* the loop. If it's still false, the key was never found. */
    if (log_key_found == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not find log_key '%s' in record",
                      ctx->log_key);
    }

    /* If nothing was read, destroy buffer */
    if (val_offset == 0) {
        flb_free(val_buf);
        return NULL;
    }
    val_buf[val_offset] = '\0';

    /* Create output buffer to store contents */
    out_buf = flb_sds_create(val_buf);
    if (out_buf == NULL) {
        flb_plg_error(ctx->ins, "Error creating buffer to store log_key contents.");
        flb_errno();
    }
    flb_free(val_buf);

    return out_buf;
}

static int count_mp_with_threshold(size_t last_offset, size_t threshold,
                                   struct flb_log_event_decoder *log_decoder,
                                   struct flb_chronicle *ctx)
{
    int ret;
    int array_size = 0;
    size_t off = 0;
    struct flb_log_event log_event;

    /* Adjust decoder offset */
    if (last_offset != 0) {
        log_decoder->offset = last_offset;
    }

    while ((ret = flb_log_event_decoder_next(
                    log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        off = log_decoder->offset;
        array_size++;

        if (off >= (threshold + last_offset)) {
            flb_plg_debug(ctx->ins,
                          "the offset %zu is exceeded the threshold %zu. "
                          "Splitting the payload over the threshold so the processed array size is %d",
                          off, threshold, array_size);

            break;
        }
    }

    return array_size;
}

static int chronicle_format(const void *data, size_t bytes,
                            const char *tag, size_t tag_len,
                            char **out_data, size_t *out_size,
                            size_t last_offset,
                            size_t threshold, size_t *out_offset,
                            struct flb_log_event_decoder *log_decoder,
                            struct flb_chronicle *ctx)
{
    int len;
    int ret;
    int array_size = 0;
    size_t off = 0;
    size_t last_off = 0;
    size_t alloc_size = 0;
    size_t s;
    char time_formatted[255];
    /* Parameters for Timestamp */
    struct tm tm;
    flb_sds_t out_buf;
    struct flb_log_event log_event;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    flb_sds_t log_text = NULL;
    int log_text_size;

    array_size = count_mp_with_threshold(last_offset, threshold, log_decoder, ctx);

    /* Reset the decoder state */
    flb_log_event_decoder_reset(log_decoder, (char *) data, bytes);

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Pack root map (unstructured log):
     * see: https://cloud.google.com/chronicle/docs/reference/ingestion-api#request_body_2
     * {
     *   "customer_id": "c8c65bfa-5f2c-42d4-9189-64bb7b939f2c",
     *   "log_type": "BIND_DNS",
     *   "entries": [
     *     {
     *       "log_text": "26-Feb-2019 13:35:02.187 client 10.120.20.32#4238: query: altostrat.com IN A + (203.0.113.102)",
     *       "ts_epoch_microseconds": 1551188102187000
     *     },
     *     {
     *       "log_text": "26-Feb-2019 13:37:04.523 client 10.50.100.33#1116: query: examplepetstore.com IN A + (203.0.113.102)",
     *       "ts_rfc3339": "2019-26-02T13:37:04.523-08:00"
     *     },
     *     {
     *       "log_text": "26-Feb-2019 13:39:01.115 client 10.1.2.3#3333: query: www.example.com IN A + (203.0.113.102)"
     *     },
     *   ]
     * }
     */
    msgpack_pack_map(&mp_pck, 3);

    msgpack_pack_str(&mp_pck, 11);
    msgpack_pack_str_body(&mp_pck, "customer_id", 11);

    msgpack_pack_str(&mp_pck, strlen(ctx->customer_id));
    msgpack_pack_str_body(&mp_pck, ctx->customer_id, strlen(ctx->customer_id));

    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "log_type", 8);

    msgpack_pack_str(&mp_pck, strlen(ctx->log_type));
    msgpack_pack_str_body(&mp_pck, ctx->log_type, strlen(ctx->log_type));

    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "entries", 7);

    /* Append entries */
    msgpack_pack_array(&mp_pck, array_size);

    flb_plg_trace(ctx->ins, "last offset is %zu", last_offset);
    /* Adjust decoder offset */
    if (last_offset != 0) {
        log_decoder->offset = last_offset;
    }

    while ((ret = flb_log_event_decoder_next(
                    log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        off = log_decoder->offset;
        alloc_size = (off - last_off) + 128; /* JSON is larger than msgpack */
        last_off = off;

        /*
         * Pack entries
         *
         * {
         *  "log_text": {...},
         *  "ts_rfc3339": "..."
         * }
         *
         */
        msgpack_pack_map(&mp_pck, 2);

        /* log_text */
        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "log_text", 8);
        if (ctx->log_key != NULL) {
            log_text = flb_pack_msgpack_extract_log_key(ctx, bytes, log_event);
            log_text_size = flb_sds_len(log_text);
        }
        else {
            log_text = flb_msgpack_to_json_str(alloc_size, log_event.body);
            log_text_size = strlen(log_text);
        }

        if (log_text == NULL) {
            flb_plg_error(ctx->ins, "Could not marshal msgpack to output string");
            return -1;
        }
        msgpack_pack_str(&mp_pck, log_text_size);
        msgpack_pack_str_body(&mp_pck, log_text, log_text_size);

        if (ctx->log_key != NULL) {
            flb_sds_destroy(log_text);
        }
        else {
            flb_free(log_text);
        }
        /* timestamp */
        msgpack_pack_str(&mp_pck, 10);
        msgpack_pack_str_body(&mp_pck, "ts_rfc3339", 10);

        gmtime_r(&log_event.timestamp.tm.tv_sec, &tm);
        s = strftime(time_formatted, sizeof(time_formatted) - 1,
                        FLB_STD_TIME_FMT, &tm);
        len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                       ".%03" PRIu64 "Z",
                       (uint64_t) log_event.timestamp.tm.tv_nsec);
        s += len;

        msgpack_pack_str(&mp_pck, s);
        msgpack_pack_str_body(&mp_pck, time_formatted, s);

        if (off >= (threshold + last_offset)) {
            flb_plg_debug(ctx->ins,
                          "the offset %zu is exceeded the threshold %zu. "
                          "Splitting the payload over the threshold so the processed array size has %d.",
                          off, threshold, array_size);

            break;
        }
    }

    /* Convert from msgpack to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        flb_plg_error(ctx->ins, "error formatting JSON payload");
        return -1;
    }

    *out_offset = last_off;
    *out_data = out_buf;
    *out_size = flb_sds_len(out_buf);

    return 0;
}

static void cb_chronicle_flush(struct flb_event_chunk *event_chunk,
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
    struct flb_chronicle *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct flb_log_event_decoder log_decoder;
    size_t threshold = 0.8 * 1024 * 1024;
    size_t offset = 0;
    size_t out_offset = 0;
    int need_loop = FLB_TRUE;
    const int retry_limit = 8;
    int retries = 0;
    const size_t one_mebibyte = 1024 * 1024;

    flb_plg_trace(ctx->ins, "flushing bytes %zu", event_chunk->size);

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Get or renew Token */
    token = get_google_token(ctx);

    if (!token) {
        flb_plg_error(ctx->ins, "cannot retrieve oauth2 token");
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_plg_trace(ctx->ins, "msgpack payload size is %zu", event_chunk->size);

    /* Prepare log decoder */
    ret = flb_log_event_decoder_init(&log_decoder, (char *) event_chunk->data, event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        /* Cleanup token and conn */
        flb_sds_destroy(token);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    while (need_loop) {
    retry:
        if (retries > 0) {
            /* (retry_limit - retries)/10.0 is a factor to reduce the
             * formatting payloads.
             * For the first attempt, it will get:
             * (8 - 1) / 10.0 = 0.7
             * For the second attempt, it will get:
             * (8 - 2) / 10.0 = 0.6
             * ...
             * For 7th attempt, it will get:
             * (8 - 7) / 10.0 = 0.1
             * For 8th attempt, it won't happen. Just give up for
             * formating though. :)
             */
            threshold = (retry_limit - retries)/10.0 * one_mebibyte;
        }

        /* Reformat msgpack to chronicle JSON payload */
        ret = chronicle_format(event_chunk->data, event_chunk->size,
                               event_chunk->tag, flb_sds_len(event_chunk->tag),
                               &payload_buf, &payload_size,
                               offset, threshold, &out_offset,
                               &log_decoder, ctx);
        if (ret != 0) {
            flb_upstream_conn_release(u_conn);
            flb_sds_destroy(token);
            flb_sds_destroy(payload_buf);
            flb_log_event_decoder_destroy(&log_decoder);

            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        flb_plg_debug(ctx->ins, "the last offset of msgpack decoder is %zu", out_offset);

        if (payload_size >= one_mebibyte) {
            retries++;
            if (retries >= retry_limit) {
                flb_plg_error(ctx->ins, "Retry limit is exeeced for chronicle_format");

                flb_upstream_conn_release(u_conn);
                flb_sds_destroy(token);
                flb_sds_destroy(payload_buf);
                flb_log_event_decoder_destroy(&log_decoder);

                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            flb_plg_debug(ctx->ins,
                          "HTTP request body is exeeded to %zd bytes. actual: %zu. left attempt(s): %d",
                          one_mebibyte, payload_size, retry_limit - retries);
            flb_sds_destroy(payload_buf);

            goto retry;
        }
        else {
            retries = 0;
        }

        /* Compose HTTP Client request */
        c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->endpoint,
                            payload_buf, payload_size, NULL, 0, NULL, 0);
        if (!c) {
            flb_plg_error(ctx->ins, "cannot create HTTP client context");
            flb_upstream_conn_release(u_conn);
            flb_sds_destroy(token);
            flb_sds_destroy(payload_buf);
            flb_log_event_decoder_destroy(&log_decoder);

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

        /* Validate all chunks are processed or not */
        if (out_offset >= event_chunk->size) {
            need_loop = FLB_FALSE;
        }
        /* Clean up HTTP client stuffs */
        flb_sds_destroy(payload_buf);
        flb_http_client_destroy(c);

        /* The next loop uses the returned offset */
        offset = out_offset;
    }

    /* Cleanup decoder */
    flb_log_event_decoder_destroy(&log_decoder);

    /* Cleanup token and conn */
    flb_sds_destroy(token);
    flb_upstream_conn_release(u_conn);

    /* Done */
    FLB_OUTPUT_RETURN(ret_code);
}

static int cb_chronicle_exit(void *data, struct flb_config *config)
{
    struct flb_chronicle *ctx = data;

    if (!ctx) {
        return -1;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_chronicle_conf_destroy(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_STR, "google_service_credentials", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_chronicle, credentials_file),
      "Set the path for the google service credentials file"
    },
    // set in flb_chronicle_oauth_credentials
    {
      FLB_CONFIG_MAP_STR, "service_account_email", (char *)NULL,
      0, FLB_FALSE, 0,
      "Set the service account email"
    },
    // set in flb_chronicle_oauth_credentials
    {
      FLB_CONFIG_MAP_STR, "service_account_secret", (char *)NULL,
      0, FLB_FALSE, 0,
      "Set the service account secret"
    },
    {
      FLB_CONFIG_MAP_STR, "project_id", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_chronicle, project_id),
      "Set the project id"
    },
    {
      FLB_CONFIG_MAP_STR, "customer_id", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_chronicle, customer_id),
      "Set the customer id"
    },
    {
      FLB_CONFIG_MAP_STR, "log_type", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_chronicle, log_type),
      "Set the log type"
    },
    {
      FLB_CONFIG_MAP_STR, "region", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_chronicle, region),
      "Set the region"
    },
    {
      FLB_CONFIG_MAP_STR, "log_key", NULL,
      0, FLB_TRUE, offsetof(struct flb_chronicle, log_key),
      "Set the log key"
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_chronicle_plugin = {
    .name         = "chronicle",
    .description  = "Send logs to Google Chronicle as unstructured log",
    .cb_init      = cb_chronicle_init,
    .cb_flush     = cb_chronicle_flush,
    .cb_exit      = cb_chronicle_exit,
    .config_map   = config_map,
    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
