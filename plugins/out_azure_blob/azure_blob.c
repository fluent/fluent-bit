/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_base64.h>

#include <msgpack.h>

#include "azure_blob.h"
#include "azure_blob_uri.h"
#include "azure_blob_conf.h"
#include "azure_blob_appendblob.h"
#include "azure_blob_blockblob.h"
#include "azure_blob_http.h"

#define CREATE_BLOB  1337

static int azure_blob_format(struct flb_config *config,
                             struct flb_input_instance *ins,
                             void *plugin_context,
                             void *flush_ctx,
                             int event_type,
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

static int send_blob(struct flb_config *config,
                     struct flb_input_instance *i_ins,
                     struct flb_azure_blob *ctx, char *name,
                     char *tag, int tag_len, void *data, size_t bytes)
{
    int ret;
    int compressed = FLB_FALSE;
    int content_encoding = FLB_FALSE;
    int content_type = FLB_FALSE;
    uint64_t ms = 0;
    size_t b_sent;
    void *out_buf;
    size_t out_size;
    flb_sds_t uri = NULL;
    flb_sds_t blockid = NULL;
    void *payload_buf;
    size_t payload_size;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    if (ctx->btype == AZURE_BLOB_APPENDBLOB) {
        uri = azb_append_blob_uri(ctx, tag);
    }
    else if (ctx->btype == AZURE_BLOB_BLOCKBLOB) {
        blockid = azb_block_blob_id(&ms);
        if (!blockid) {
            flb_plg_error(ctx->ins, "could not generate block id");
            return FLB_RETRY;
        }
        uri = azb_block_blob_uri(ctx, tag, blockid, ms);
    }

    if (!uri) {
        flb_free(blockid);
        return FLB_RETRY;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for append_blob");
        flb_sds_destroy(uri);
        flb_free(blockid);
        return FLB_RETRY;
    }

    /* Format the data */
    ret = azure_blob_format(config, i_ins,
                            ctx, NULL,
                            FLB_EVENT_TYPE_LOGS,
                            tag, tag_len,
                            data, bytes,
                            &out_buf, &out_size);
    if (ret != 0) {
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(uri);
        flb_free(blockid);
        return FLB_RETRY;
    }

    /* Map buffer */
    payload_buf = out_buf;
    payload_size = out_size;

    if (ctx->compress_gzip == FLB_TRUE || ctx->compress_blob == FLB_TRUE) {
        ret = flb_gzip_compress((void *) out_buf, out_size,
                                &payload_buf, &payload_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "cannot gzip payload, disabling compression");
        }
        else {
            compressed = FLB_TRUE;
            /* JSON buffer is not longer needed */
            flb_sds_destroy(out_buf);
        }
    }

    if (ctx->compress_blob == FLB_TRUE) {
        content_encoding = AZURE_BLOB_CE_NONE;
        content_type = AZURE_BLOB_CT_GZIP;
    }
    else if (compressed == FLB_TRUE) {
        content_encoding = AZURE_BLOB_CE_GZIP;
        content_type = AZURE_BLOB_CT_JSON;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_PUT,
                        uri,
                        payload_buf, payload_size, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_sds_destroy(out_buf);
        flb_upstream_conn_release(u_conn);
        flb_free(blockid);
        return FLB_RETRY;
    }

    /* Prepare headers and authentication */
    azb_http_client_setup(ctx, c, (ssize_t) payload_size, FLB_FALSE,
                          content_type, content_encoding);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    flb_sds_destroy(uri);

    /* Release */
    if (compressed == FLB_FALSE) {
        flb_sds_destroy(out_buf);
    }
    else {
        flb_free(payload_buf);
    }

    flb_upstream_conn_release(u_conn);

    /* Validate HTTP status */
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error sending append_blob");
        flb_free(blockid);
        return FLB_RETRY;
    }

    if (c->resp.status == 201) {
        flb_plg_info(ctx->ins, "content appended to blob successfully");
        flb_http_client_destroy(c);

        if (ctx->btype == AZURE_BLOB_BLOCKBLOB) {
            ret = azb_block_blob_commit(ctx, blockid, tag, ms);
            flb_free(blockid);
            return ret;
        }
        flb_free(blockid);
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

static int create_blob(struct flb_azure_blob *ctx, char *name)
{
    int ret;
    size_t b_sent;
    flb_sds_t uri = NULL;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    uri = azb_uri_create_blob(ctx, name);
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
    azb_http_client_setup(ctx, c, -1, FLB_TRUE,
                          AZURE_BLOB_CT_NONE, AZURE_BLOB_CE_NONE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    flb_sds_destroy(uri);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "error sending append_blob");
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
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
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    return FLB_OK;
}

static int create_container(struct flb_azure_blob *ctx, char *name)
{
    int ret;
    size_t b_sent;
    flb_sds_t uri;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for container creation");
        return FLB_FALSE;
    }

    /* URI */
    uri = azb_uri_ensure_or_create_container(ctx);
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
    azb_http_client_setup(ctx, c, -1, FLB_FALSE,
                          AZURE_BLOB_CT_NONE, AZURE_BLOB_CE_NONE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* Release URI */
    flb_sds_destroy(uri);

    /* Validate http response */
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error requesting container creation");
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
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
    struct flb_connection *u_conn;

    uri = azb_uri_ensure_or_create_container(ctx);
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
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }
    flb_http_strip_port_from_host(c);

    /* Prepare headers and authentication */
    azb_http_client_setup(ctx, c, -1, FLB_FALSE,
                          AZURE_BLOB_CT_NONE, AZURE_BLOB_CE_NONE);

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
                     ctx->container_name);
        ret = create_container(ctx, ctx->container_name);
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

static void cb_azure_blob_flush(struct flb_event_chunk *event_chunk,
                                struct flb_output_flush *out_flush,
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

    ret = send_blob(config, i_ins, ctx,
                    (char *) event_chunk->tag,  /* use tag as 'name' */
                    (char *) event_chunk->tag, flb_sds_len(event_chunk->tag),
                    (char *) event_chunk->data, event_chunk->size);

    if (ret == CREATE_BLOB) {
        ret = create_blob(ctx, event_chunk->tag);
        if (ret == FLB_OK) {
            ret = send_blob(config, i_ins, ctx,
                            (char *) event_chunk->tag,  /* use tag as 'name' */
                            (char *) event_chunk->tag,
                            flb_sds_len(event_chunk->tag),
                            (char *) event_chunk->data, event_chunk->size);
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
     FLB_CONFIG_MAP_STR, "blob_type", "appendblob",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, blob_type),
     "Set the block type: appendblob or blockblob"
    },

    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     "Set payload compression in network transfer. Option available is 'gzip'"
    },

    {
     FLB_CONFIG_MAP_BOOL, "compress_blob", "false",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, compress_blob),
     "Enable block blob GZIP compression in the final blob file. This option is "
     "not compatible with 'appendblob' block type"
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
