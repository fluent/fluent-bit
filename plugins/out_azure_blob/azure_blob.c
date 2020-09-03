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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>

#include <msgpack.h>

#include "azure_blob.h"
#include "azure_blob_conf.h"

#define CREATE_BLOB  1337

static flb_sds_t uri_container(struct flb_azure_blob *ctx)
{
    flb_sds_t uri;

    uri = flb_sds_create_size(256);
    if (!uri) {
        return NULL;
    }

    flb_sds_printf(&uri, "%s%s", ctx->base_uri, ctx->container_name);
    return uri;
}

static flb_sds_t uri_ensure_or_create_container(struct flb_azure_blob *ctx)
{
    flb_sds_t uri;

    uri = uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    flb_sds_printf(&uri, "?restype=container");
    return uri;
}

static flb_sds_t uri_append_blob(struct flb_azure_blob *ctx, char *tag)
{
    flb_sds_t uri;

    uri = uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    if (ctx->path) {
        flb_sds_printf(&uri, "/%s/%s?comp=appendblock",
                       ctx->path, tag);
    }
    else {
        flb_sds_printf(&uri, "/%s?comp=appendblock",
                       tag);
    }

    return uri;

}

static flb_sds_t uri_create_append_blob(struct flb_azure_blob *ctx, char *tag)
{
    flb_sds_t uri;

    uri = uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    if (ctx->path) {
        flb_sds_printf(&uri, "/%s/%s",
                       ctx->path, tag);
    }
    else {
        flb_sds_printf(&uri, "/%s", tag);
    }

    return uri;
}


static int azure_blob_format(struct flb_config *config,
                             struct flb_input_instance *ins,
                             void *plugin_context,
                             void *flush_ctx,
                             const char *tag, int tag_len,
                             const void *data, size_t bytes,
                             void **out_data, size_t *out_size)
{
    flb_sds_t out_buf;
    struct flb_azure_blob *ctx = plugin_context;

    out_buf = flb_pack_msgpack_to_json_format(data, bytes,
                                              FLB_PACK_JSON_FORMAT_LINES,
                                              FLB_PACK_JSON_DATE_ISO8601,
                                              ctx->date_key);
    if (!out_buf) {
        return -1;
    }

    *out_data = out_buf;
    *out_size = flb_sds_len(out_buf);
    return 0;
}

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
    int i;
    int pos;
    int len;
    size_t size;
    flb_sds_t cr;
    flb_sds_t tmp;

    len = strlen(c->uri);
    size = flb_sds_len(ctx->account_name) + len + 64;

    cr = flb_sds_create_size(size);
    if (!cr) {
        return NULL;
    }

    tmp = flb_sds_printf(&cr, "/%s%s", ctx->account_name, c->uri);
    if (!tmp) {
        flb_sds_destroy(cr);
        return NULL;
    }

    pos = 1 + flb_sds_len(ctx->account_name);
    for (i = pos; i < flb_sds_len(cr); i++) {
        if (cr[i] == '?') {
            cr[i] = '\n';
        }
        else if (cr[i] == '=') {
            cr[i] = ':';
        }
    }

    return cr;
}

static flb_sds_t canonical_request(struct flb_azure_blob *ctx,
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
    flb_sds_t b64 = NULL;
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

static int http_client_setup(struct flb_azure_blob *ctx,
                             struct flb_http_client *c,
                             size_t content_length,
                             int content_type,
                             int append_blob)
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
    if (append_blob == FLB_TRUE) {
        flb_http_add_header(c, "x-ms-blob-type", 14, "AppendBlob", 10);
    }

    /* Azure header: x-ms-date */
    now = time(NULL);
    gmtime_r(&now, &tm);
    len = strftime(tmp, sizeof(tmp) - 1, "%a, %d %b %Y %H:%M:%S GMT", &tm);

    flb_http_add_header(c, "x-ms-date", 9, tmp, len);

    /* Azure header: x-ms-version */
    flb_http_add_header(c, "x-ms-version", 12, "2019-12-12", 10);

    can_req = canonical_request(ctx, c, content_length, content_type);

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

static int create_container(struct flb_azure_blob *ctx, char *name)
{
    int ret;
    size_t b_sent;
    flb_sds_t uri;
    struct flb_http_client *c;
    struct flb_upstream_conn *u_conn;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for container creation");
        return FLB_FALSE;
    }

    /* URI */
    uri = uri_ensure_or_create_container(ctx);
    if (!uri) {
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_PUT,
                        uri,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }

    /* Prepare headers and authentication */
    http_client_setup(ctx, c, -1, FLB_FALSE, FLB_FALSE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* Release URI */
    flb_sds_destroy(uri);

    /* Validate http response */
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error requesting container creation");
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return FLB_FALSE;
    }

    if (c->resp.status == 201) {
        flb_plg_info(ctx->ins, "container '%s' created sucessfully", name);
    }
    else {
        if (c->resp.payload_size > 0) {
            flb_plg_error(ctx->ins, "cannot create container '%s'\n%s",
                          name, c->resp.payload);
        }
        else {
            flb_plg_error(ctx->ins, "cannot create container '%s'\n%s",
                          name, c->resp.payload);
        }
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    return FLB_TRUE;
}

static int append_blob(struct flb_config *config,
                       struct flb_input_instance *i_ins,
                       struct flb_azure_blob *ctx, char *name,
                       char *tag, int tag_len, void *data, size_t bytes)

{
    int ret;
    size_t b_sent;
    void *out_buf;
    size_t out_size;
    flb_sds_t uri;
    struct flb_http_client *c;
    struct flb_upstream_conn *u_conn;

    uri = uri_append_blob(ctx, tag);
    if (!uri) {
        return FLB_RETRY;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for append_blob");
        flb_sds_destroy(uri);
        return FLB_RETRY;
    }

    /* Format the data */
    ret = azure_blob_format(config, i_ins,
                            ctx, NULL,
                            tag, tag_len,
                            data, bytes,
                            &out_buf, &out_size);
    if (ret != 0) {
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(uri);
        return FLB_RETRY;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_PUT,
                        uri,
                        out_buf, out_size, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_sds_destroy(out_buf);
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }

    /* Prepare headers and authentication */
    http_client_setup(ctx, c, out_size, FLB_FALSE, FLB_FALSE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    flb_sds_destroy(uri);

    /* Release */
    flb_sds_destroy(out_buf);
    flb_upstream_conn_release(u_conn);

    /* Validate HTTP status */
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error sending append_blob");
        return FLB_RETRY;
    }

    if (c->resp.status == 201) {
        flb_plg_info(ctx->ins, "content appended to blob successfully");
        flb_http_client_destroy(c);
        return FLB_OK;
    }
    else if (c->resp.status == 404) {
        flb_plg_info(ctx->ins, "blob not found: %s", c->uri);
        flb_http_client_destroy(c);
        return CREATE_BLOB;
    }
    else if (c->resp.payload_size > 0) {
        flb_plg_error(ctx->ins, "cannot append content to blob\n%s",
                      c->resp.payload);
        if (strstr(c->resp.payload, "must be 0 for Create Append")) {
            flb_http_client_destroy(c);
            return CREATE_BLOB;
        }
    }
    else {
        flb_plg_error(ctx->ins, "cannot append content to blob");
    }
    flb_http_client_destroy(c);

    return FLB_RETRY;
}

static int create_append_blob(struct flb_azure_blob *ctx, char *name)
{
    int ret;
    size_t b_sent;
    flb_sds_t uri;
    struct flb_http_client *c;
    struct flb_upstream_conn *u_conn;

    uri = uri_create_append_blob(ctx, name);
    if (!uri) {
        return FLB_RETRY;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for create_append_blob");
        flb_sds_destroy(uri);
        return FLB_RETRY;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_PUT,
                        uri,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(uri);
        return FLB_RETRY;
    }

    /* Prepare headers and authentication */
    http_client_setup(ctx, c, -1, FLB_FALSE, FLB_TRUE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    flb_sds_destroy(uri);
    flb_upstream_conn_release(u_conn);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "error sending append_blob");
        flb_http_client_destroy(c);
        return FLB_RETRY;
    }

    if (c->resp.status == 201) {
        flb_plg_info(ctx->ins, "blob created successfully: %s", c->uri);
    }
    else {
        if (c->resp.payload_size > 0) {
            flb_plg_error(ctx->ins, "http_status=%i cannot create append blob\n%s",
                          c->resp.status, c->resp.payload);
        }
        else {
            flb_plg_error(ctx->ins, "http_status=%i cannot create append blob",
                          c->resp.status);
        }
        flb_http_client_destroy(c);
        return FLB_RETRY;
    }

    flb_http_client_destroy(c);
    return FLB_OK;
}

/*
 * Check that the container exists, if it doesn't and the configuration property
 * auto_create_container is enabled, it will send a request to create it. If it
 * could not be created or auto_create_container is disabled, it returns FLB_FALSE.
 */
static int ensure_container(struct flb_azure_blob *ctx)
{
    int ret;
    int status;
    size_t b_sent;
    flb_sds_t uri;
    struct flb_http_client *c;
    struct flb_upstream_conn *u_conn;

    uri = uri_ensure_or_create_container(ctx);
    if (!uri) {
        return FLB_FALSE;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for container check");
        flb_sds_destroy(uri);
        return FLB_FALSE;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_GET,
                        uri,
                        NULL, 0, NULL, 0, NULL, 0);
    flb_http_strip_port_from_host(c);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }

    /* Prepare headers and authentication */
    http_client_setup(ctx, c, -1, FLB_FALSE, FLB_FALSE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    flb_sds_destroy(uri);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "error requesting container properties");
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }

    status = c->resp.status;
    flb_http_client_destroy(c);

    /* Release connection */
    flb_upstream_conn_release(u_conn);

    /* Request was successful, validate HTTP status code */
    if (status == 404) {
        /* The container was not found, try to create it */
        flb_plg_info(ctx->ins, "container '%s' not found, trying to create it",
                     "mycontainer");
        ret = create_container(ctx, "mycontainer");
        return ret;
    }
    else if (status == 200) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int cb_azure_blob_init(struct flb_output_instance *ins,
                              struct flb_config *config, void *data)
{
    struct flb_azure_blob *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_azure_blob_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    flb_output_set_http_debug_callbacks(ins);
    return 0;
}

static void cb_azure_blob_flush(const void *data, size_t bytes,
                                const char *tag, int tag_len,
                                struct flb_input_instance *i_ins,
                                void *out_context,
                                struct flb_config *config)
{
    int ret;
    struct flb_azure_blob *ctx = out_context;
    (void) i_ins;
    (void) config;

    /* Validate the container exists, otherwise just create it */
    ret = ensure_container(ctx);
    if (ret == FLB_FALSE) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    ret = append_blob(config, i_ins, ctx, (char *) tag,
                      (char *) tag, tag_len, (char *) data, bytes);
    if (ret == CREATE_BLOB) {
        ret = create_append_blob(ctx, (char *) tag);
        if (ret == FLB_OK) {
            ret = append_blob(config, i_ins, ctx, (char *) tag,
                              (char *) tag, tag_len, (char *) data, bytes);
        }
    }

    /* FLB_RETRY, FLB_OK, FLB_ERROR */
    FLB_OUTPUT_RETURN(ret);
}

static int cb_azure_blob_exit(void *data, struct flb_config *config)
{
    struct flb_azure_blob *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_azure_blob_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "account_name", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, account_name),
     "Azure account name (mandatory)"
    },

    {
     FLB_CONFIG_MAP_STR, "container_name", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, container_name),
     "Container name (mandatory)"
    },

    {
     FLB_CONFIG_MAP_BOOL, "auto_create_container", "true",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, auto_create_container),
     "Auto create container if it don't exists"
    },

    {
     FLB_CONFIG_MAP_BOOL, "emulator_mode", "false",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, emulator_mode),
     "Use emulator mode, enable it if you want to use Azurite"
    },

    {
     FLB_CONFIG_MAP_STR, "shared_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, shared_key),
     "Azure shared key"
    },

    {
     FLB_CONFIG_MAP_STR, "endpoint", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, endpoint),
     "Custom full URL endpoint to use an emulator"
    },

    {
     FLB_CONFIG_MAP_STR, "path", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, path),
     "Set a path for your blob"
    },

    {
     FLB_CONFIG_MAP_STR, "date_key", "@timestamp",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, date_key),
     "Name of the key that will have the record timestamp"
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_azure_blob_plugin = {
    .name         = "azure_blob",
    .description  = "Azure Blob Storage",
    .cb_init      = cb_azure_blob_init,
    .cb_flush     = cb_azure_blob_flush,
    .cb_exit      = cb_azure_blob_exit,

    /* Test */
    .test_formatter.callback = azure_blob_format,

    .config_map   = config_map,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
