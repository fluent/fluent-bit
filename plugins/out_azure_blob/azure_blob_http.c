/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>
#include <mbedtls/base64.h>

#include "azure_blob.h"
#include "azure_blob_uri.h"

static int hmac_sha256_sign(unsigned char out[32],
                            unsigned char *key, size_t key_len,
                            unsigned char *msg, size_t msg_len)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);

    /* Start with the key */
    mbedtls_md_hmac_starts(&ctx, key, key_len);

    /* Update message */
    mbedtls_md_hmac_update(&ctx, msg, msg_len);

    /* Write digest to output buffer */
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);

    return 0;
}

static flb_sds_t canonical_headers(struct flb_http_client *c)
{
    flb_sds_t ch;
    flb_sds_t tmp;
    struct flb_kv *kv;
    struct mk_list *head;

    ch = flb_sds_create_size(mk_list_size(&c->headers) * 64);
    if (!ch) {
        return NULL;
    }

    mk_list_foreach(head, &c->headers) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strncmp(kv->key, "x-ms-", 5) != 0) {
            continue;
        }

        /* key */
        tmp = flb_sds_cat(ch, kv->key, flb_sds_len(kv->key));
        if (!tmp) {
            flb_sds_destroy(ch);
            return NULL;
        }
        ch = tmp;

        /* sep */
        tmp = flb_sds_cat(ch, ":", 1);
        if (!tmp) {
            flb_sds_destroy(ch);
            return NULL;
        }
        ch = tmp;

        /* value */
        tmp = flb_sds_cat(ch, kv->val, flb_sds_len(kv->val));
        if (!tmp) {
            flb_sds_destroy(ch);
            return NULL;
        }
        ch = tmp;

        tmp = flb_sds_cat(ch, "\n", 1);
        if (!tmp) {
            flb_sds_destroy(ch);
            return NULL;
        }
        ch = tmp;
    }

    return ch;
}

static flb_sds_t canonical_resource(struct flb_azure_blob *ctx,
                                    struct flb_http_client *c)
{
    int pos;
    int len;
    int kv_start;
    char *p;
    size_t size;
    flb_sds_t cr;
    flb_sds_t dec_uri;
    flb_sds_t tmp;

    len = strlen(c->uri);
    size = flb_sds_len(ctx->account_name) + len + 64;

    cr = flb_sds_create_size(size);
    if (!cr) {
        return NULL;
    }

    dec_uri = azb_uri_decode(c->uri, len);
    tmp = flb_sds_printf(&cr, "/%s%s", ctx->account_name, dec_uri);
    if (!tmp) {
        flb_sds_destroy(dec_uri);
        flb_sds_destroy(cr);
        return NULL;
    }
    flb_sds_destroy(dec_uri);

    pos = 1 + flb_sds_len(ctx->account_name);

    p = strchr(cr + pos, '?');
    if (p) {
        kv_start = FLB_TRUE;
        while (*p) {
            if (*p == '?') {
                *p = '\n';
            }
            else if (*p == '=' && kv_start == FLB_TRUE) {
                *p = ':';
                kv_start = FLB_FALSE;
            }
            else if (*p == '&') {
                *p = '\n';
                kv_start = FLB_TRUE;
            }
            p++;
        }
    }

    return cr;
}

flb_sds_t azb_http_canonical_request(struct flb_azure_blob *ctx,
                                     struct flb_http_client *c,
                                     ssize_t content_length,
                                     int content_type)
{
    int ret;
    size_t size;
    size_t o_len = 0;
    flb_sds_t can_req;
    flb_sds_t can_res;
    flb_sds_t can_headers;
    flb_sds_t tmp = NULL;
    char *b64 = NULL;
    unsigned char signature[32];

    size = strlen(c->uri) + (mk_list_size(&c->headers) * 64) + 256;
    can_req = flb_sds_create_size(size);
    if (!can_req) {
        flb_plg_error(ctx->ins, "cannot allocate buffer for canonical request");
        return NULL;
    }

    switch (c->method) {
    case FLB_HTTP_GET:
        tmp = flb_sds_cat(can_req, "GET\n", 4);
        break;
    case FLB_HTTP_POST:
        tmp = flb_sds_cat(can_req, "POST\n", 5);
        break;
    case FLB_HTTP_PUT:
        tmp = flb_sds_cat(can_req, "PUT\n", 4);
        break;
    };

    if (!tmp) {
        flb_plg_error(ctx->ins, "invalid processing HTTP method");
        flb_sds_destroy(can_req);
        return NULL;
    }

    flb_sds_printf(&can_req,
                   "\n"           /* Content-Encoding */
                   "\n"           /* Content-Language */
                   );

    if (content_length >= 0) {
        flb_sds_printf(&can_req,
                       "%i\n"     /* Content-Length */,
                       content_length);
    }
    else {
        flb_sds_printf(&can_req,
                       "\n"       /* Content-Length */
                       );
    }

    flb_sds_printf(&can_req,
                   "\n"    /* Content-MD5 */
                   "%s\n"  /* Content-Type */
                   "\n"    /* Date */
                   "\n"    /* If-Modified-Since */
                   "\n"    /* If-Match */
                   "\n"    /* If-None-Match */
                   "\n"    /* If-Unmodified-Since */
                   "\n"    /* Range */,
                   content_type ? AZURE_BLOB_CT_JSON: "");

    /* Append canonicalized headers */
    can_headers = canonical_headers(c);
    if (!can_headers) {
        flb_sds_destroy(can_req);
        return NULL;
    }
    tmp = flb_sds_cat(can_req, can_headers, flb_sds_len(can_headers));
    if (!tmp) {
        flb_sds_destroy(can_req);
        flb_sds_destroy(can_headers);
        return NULL;
    }
    can_req = tmp;
    flb_sds_destroy(can_headers);

    /* Append canonical resource */
    can_res = canonical_resource(ctx, c);
    if (!can_res) {
        flb_sds_destroy(can_req);
        return NULL;
    }
    tmp = flb_sds_cat(can_req, can_res, flb_sds_len(can_res));
    if (!tmp) {
        flb_sds_destroy(can_res);
        flb_sds_destroy(can_req);
        flb_sds_destroy(can_headers);
        return NULL;
    }
    can_req = tmp;
    flb_sds_destroy(can_res);

    flb_plg_trace(ctx->ins, "string to sign\n%s", can_req);

    /* Signature */
    hmac_sha256_sign(signature, ctx->decoded_sk, ctx->decoded_sk_size,
                     (unsigned char *) can_req, flb_sds_len(can_req));
    flb_sds_destroy(can_req);

    /* base64 decoded size */
    size = ((4 * ((sizeof(signature) + 1)) / 3) + 1);
    b64 = flb_sds_create_size(size);
    if (!b64) {
        return NULL;
    }

    ret = mbedtls_base64_encode((unsigned char *) b64, size, &o_len,
                                signature, sizeof(signature));
    if (ret != 0) {
        flb_sds_destroy(can_req);
        return NULL;
    }
    flb_sds_len_set(b64, o_len);

    return b64;
}

int azb_http_client_setup(struct flb_azure_blob *ctx, struct flb_http_client *c,
                          ssize_t content_length, int content_type,
                          int blob_type)
{
    int len;
    time_t now;
    struct tm tm;
    char tmp[64];
    flb_sds_t can_req;
    flb_sds_t auth;

    /* Header: User Agent */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    /* Header: Content-Type */
    if (content_type == FLB_TRUE) {
        flb_http_add_header(c,
                            AZURE_BLOB_CT, sizeof(AZURE_BLOB_CT) - 1,
                            AZURE_BLOB_CT_JSON, sizeof(AZURE_BLOB_CT_JSON) - 1);
    }

    /* Azure header: x-ms-blob-type */
    if (blob_type == FLB_TRUE) {
        if (ctx->btype == AZURE_BLOB_APPENDBLOB) {
            flb_http_add_header(c, "x-ms-blob-type", 14, "AppendBlob", 10);
        }
        else if (ctx->btype == AZURE_BLOB_BLOCKBLOB) {
            flb_http_add_header(c, "x-ms-blob-type", 14, "BlockBlob", 9);
        }
    }

    /* Azure header: x-ms-date */
    now = time(NULL);
    gmtime_r(&now, &tm);
    len = strftime(tmp, sizeof(tmp) - 1, "%a, %d %b %Y %H:%M:%S GMT", &tm);

    flb_http_add_header(c, "x-ms-date", 9, tmp, len);

    /* Azure header: x-ms-version */
    flb_http_add_header(c, "x-ms-version", 12, "2019-12-12", 10);

    can_req = azb_http_canonical_request(ctx, c, content_length, content_type);

    auth = flb_sds_create_size(64 + flb_sds_len(can_req));

    flb_sds_cat(auth, ctx->shared_key_prefix, flb_sds_len(ctx->shared_key_prefix));
    flb_sds_cat(auth, can_req, flb_sds_len(can_req));

    /* Azure header: authorization */
    flb_http_add_header(c, "Authorization", 13, auth, flb_sds_len(auth));

    /* Release buffers */
    flb_sds_destroy(can_req);
    flb_sds_destroy(auth);

    /* Set callback context to the HTTP client context */
    flb_http_set_callback_context(c, ctx->ins->callback);

    return 0;
}
