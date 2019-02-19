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
#include <msgpack.h>

#include "azure.h"
#include "azure_conf.h"
#include <mbedtls/base64.h>

static int cb_azure_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_azure *ctx;

    ctx = flb_azure_conf_create(ins, config);
    if (!ctx) {
        flb_error("[out_azure] configuration failed");
        return -1;
    }

    flb_output_set_context(ins, ctx);
    return 0;
}

int azure_format(void *in_buf, size_t in_bytes,
                  char **out_buf, size_t *out_size,
                  struct flb_azure *ctx)
{
    int i;
    int array_size = 0;
    int map_size;
    size_t off = 0;
    double t;
    struct flb_time tm;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object *obj;
    msgpack_object map;
    msgpack_object k;
    msgpack_object v;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    flb_sds_t record;

    /* Count number of items */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, in_buf, in_bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        array_size++;
    }
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, array_size);

    off = 0;
    while (msgpack_unpack_next(&result, in_buf, in_bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;

        /* Get timestamp */
        flb_time_pop_from_msgpack(&tm, &result, &obj);
        t = flb_time_to_double(&tm);

        /* Create temporal msgpack buffer */
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

        map = root.via.array.ptr[1];
        map_size = map.via.map.size;

        msgpack_pack_map(&mp_pck, map_size + 1);

        /* Append the time key */
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->time_key));
        msgpack_pack_str_body(&mp_pck,
                              ctx->time_key,
                              flb_sds_len(ctx->time_key));
        msgpack_pack_double(&mp_pck, t);

        /* Append original map k/v */
        for (i = 0; i < map_size; i++) {
            k = map.via.map.ptr[i].key;
            v = map.via.map.ptr[i].val;

            msgpack_pack_object(&tmp_pck, k);
            msgpack_pack_object(&tmp_pck, v);
        }
        msgpack_sbuffer_write(&mp_sbuf, tmp_sbuf.data, tmp_sbuf.size);
        msgpack_sbuffer_destroy(&tmp_sbuf);
    }

    record = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    if (!record) {
        flb_errno();
        msgpack_sbuffer_destroy(&mp_sbuf);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);

    *out_buf = record;
    *out_size = flb_sds_len(record);

    return 0;
}

static int build_headers(struct flb_http_client *c,
                         size_t content_length,
                         struct flb_azure *ctx)
{
    int len;
    char *auth;
    char tmp[256];
    time_t t;
    size_t size;
    size_t olen;
    flb_sds_t rfc1123date;
    flb_sds_t str_hash;
    struct tm tm = {0};
    unsigned char hmac_hash[32] = {0};
    mbedtls_md_context_t mctx;

    /* Format Date */
    rfc1123date = flb_sds_create_size(32);
    if (!rfc1123date) {
        flb_errno();
        return -1;
    }

    t = time(NULL);
    if (!gmtime_r(&t, &tm)) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return -1;
    }
    size = strftime(rfc1123date,
                    flb_sds_alloc(rfc1123date) - 1,
                    "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (size <= 0) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return -1;
    }
    flb_sds_len_set(rfc1123date, size);

    /* Compose source string for the hash */
    str_hash = flb_sds_create_size(256);
    if (!str_hash) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return -1;
    }

    len = snprintf(tmp, sizeof(tmp) - 1, "%zu\n", content_length);
    flb_sds_cat(str_hash, "POST\n", 5);
    flb_sds_cat(str_hash, tmp, len);
    flb_sds_cat(str_hash, "application/json\n", 17);
    flb_sds_cat(str_hash, "x-ms-date:", 10);
    flb_sds_cat(str_hash, rfc1123date, flb_sds_len(rfc1123date));
    flb_sds_cat(str_hash, "\n", 1);
    flb_sds_cat(str_hash, FLB_AZURE_RESOURCE, sizeof(FLB_AZURE_RESOURCE) - 1);

    /* Authorization signature */
    mbedtls_md_init(&mctx);
    mbedtls_md_setup(&mctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256) , 1);
    mbedtls_md_hmac_starts(&mctx, (unsigned char *) ctx->dec_shared_key,
                           flb_sds_len(ctx->dec_shared_key));
    mbedtls_md_hmac_update(&mctx, (unsigned char *) str_hash,
                           flb_sds_len(str_hash));
    mbedtls_md_hmac_finish(&mctx, hmac_hash);
    mbedtls_md_free(&mctx);

    /* Encoded hash */
    mbedtls_base64_encode((unsigned char *) &tmp, sizeof(tmp) - 1, &olen,
                          hmac_hash, sizeof(hmac_hash));
    tmp[olen] = '\0';

    /* Append headers */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Log-Type", 8,
                        ctx->log_type, flb_sds_len(ctx->log_type));
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    flb_http_add_header(c, "x-ms-date", 9, rfc1123date,
                        flb_sds_len(rfc1123date));

    size = 32 + flb_sds_len(ctx->customer_id) + olen;
    auth = flb_malloc(size);
    if (!auth) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        flb_sds_destroy(str_hash);
        return -1;
    }


    len = snprintf(auth, size, "SharedKey %s:%s",
                   ctx->customer_id, tmp);
    flb_http_add_header(c, "Authorization", 13, auth, len);

    /* release resources */
    flb_sds_destroy(rfc1123date);
    flb_sds_destroy(str_hash);
    flb_free(auth);

    return 0;
}

static void cb_azure_flush(void *data, size_t bytes,
                            char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    int ret;
    size_t b_sent;
    char *buf_data;
    size_t buf_size;
    struct flb_azure *ctx = out_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    flb_sds_t payload;
    (void) i_ins;
    (void) config;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Convert binary logs into a JSON payload */
    ret = azure_format(data, bytes, &buf_data, &buf_size, ctx);
    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    payload = (flb_sds_t) buf_data;

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        buf_data, buf_size, NULL, 0, NULL, 0);
    flb_http_buffer_size(c, FLB_HTTP_DATA_SIZE_MAX);

    /* Append headers and Azure signature */
    ret = build_headers(c, flb_sds_len(payload), ctx);
    if (ret == -1) {
        flb_error("[out_azure] error composing signature");
        flb_sds_destroy(payload);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[out_azure] http_do=%i", ret);
        goto retry;
    }
    else {
        if (c->resp.status >= 200 && c->resp.status <= 299) {
            flb_info("[out_azure] customer_id=%s, HTTP status=%i",
                     ctx->customer_id, c->resp.status);
        }
        else {
            if (c->resp.payload_size > 0) {
                flb_warn("[out_azure] http_status=%i:\n%s",
                         c->resp.status, c->resp.payload);
            }
            else {
                flb_warn("[out_azure] http_status=%i", c->resp.status);
            }
            goto retry;
        }
    }

    /* Cleanup */
    flb_http_client_destroy(c);
    flb_sds_destroy(payload);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);

    /* Issue a retry */
 retry:
    flb_http_client_destroy(c);
    flb_sds_destroy(payload);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_RETRY);
}

static int cb_azure_exit(void *data, struct flb_config *config)
{
    struct flb_azure *ctx = data;

    flb_azure_conf_destroy(ctx);
    return 0;
}

struct flb_output_plugin out_azure_plugin = {
    .name         = "azure",
    .description  = "Send events to Azure HTTP Event Collector",
    .cb_init      = cb_azure_init,
    .cb_flush     = cb_azure_flush,
    .cb_exit      = cb_azure_exit,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
