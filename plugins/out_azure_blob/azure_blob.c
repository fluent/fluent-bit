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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_input_blob.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_notification.h>

#include <msgpack.h>

#include "azure_blob.h"
#include "azure_blob_uri.h"
#include "azure_blob_conf.h"
#include "azure_blob_appendblob.h"
#include "azure_blob_blockblob.h"
#include "azure_blob_http.h"

#ifdef FLB_HAVE_SQLDB
#include "azure_blob_db.h"
#endif

#define CREATE_BLOB  1337

/* thread_local_storage for workers */

struct worker_info {
    int active_upload;
};

FLB_TLS_DEFINE(struct worker_info, worker_info);

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
        /* delete "&sig=..." in the c->uri for security */
        char *p = strstr(c->uri, "&sig=");
        if (p) {
            *p = '\0';
        }
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

#ifdef FLB_HAVE_SQLDB
static int delete_blob(struct flb_azure_blob *ctx, char *name)
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
    c = flb_http_client(u_conn, FLB_HTTP_DELETE,
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
        /* delete "&sig=..." in the c->uri for security */
        char *p = strstr(c->uri, "&sig=");
        if (p) {
            *p = '\0';
        }
        flb_plg_info(ctx->ins, "blob deleted successfully: %s", c->uri);
    }
    else {
        if (c->resp.payload_size > 0) {
            flb_plg_error(ctx->ins, "http_status=%i cannot delete append blob\n%s",
                          c->resp.status, c->resp.payload);
        }
        else {
            flb_plg_error(ctx->ins, "http_status=%i cannot delete append blob",
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
#endif

static int http_send_blob(struct flb_config *config, struct flb_azure_blob *ctx,
                          flb_sds_t ref_name,
                          flb_sds_t uri,
                          flb_sds_t block_id,
                          int event_type,
                          void *data, size_t bytes)
{
    int ret;
    int compressed = FLB_FALSE;
    int content_encoding = FLB_FALSE;
    int content_type = FLB_FALSE;
    size_t b_sent;
    void *payload_buf;
    size_t payload_size;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create TCP upstream connection");
        return FLB_RETRY;
    }

    payload_buf = data;
    payload_size = bytes;

    /* Handle compression requests */
    if (ctx->compress_gzip == FLB_TRUE || ctx->compress_blob == FLB_TRUE) {
        ret = flb_gzip_compress((void *) data, bytes, &payload_buf, &payload_size);
        if (ret == 0) {
            compressed = FLB_TRUE;
        }
        else {
            flb_plg_warn(ctx->ins,
                        "cannot gzip payload, disabling compression");
            payload_buf = data;
            payload_size = bytes;
        }
    }

    /* set http header flags */
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
        if (compressed == FLB_TRUE) {
            flb_free(payload_buf);
        }
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }

    /* Prepare headers and authentication */
    azb_http_client_setup(ctx, c, (ssize_t) payload_size, FLB_FALSE,
                          content_type, content_encoding);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* Release compressed buffer */
    if (compressed == FLB_TRUE) {
        flb_free(payload_buf);
    }

    flb_upstream_conn_release(u_conn);

    /* Validate HTTP status */
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error sending append_blob for %s", ref_name);
        return FLB_RETRY;
    }

    if (c->resp.status == 201) {
        flb_plg_info(ctx->ins, "content uploaded successfully: %s", ref_name);
        flb_http_client_destroy(c);
        return FLB_OK;
    }
    else if (c->resp.status == 404) {
        /* delete "&sig=..." in the c->uri for security */
        char *p = strstr(c->uri, "&sig=");
        if (p) {
            *p = '\0';
        }

        flb_plg_info(ctx->ins, "blob not found: %s", c->uri);
        flb_http_client_destroy(c);
        return CREATE_BLOB;
    }
    else if (c->resp.payload_size > 0) {
        flb_plg_error(ctx->ins, "http_status=%i cannot append content to blob\n%s",
                      c->resp.status, c->resp.payload);
        if (strstr(c->resp.payload, "must be 0 for Create Append")) {
            flb_http_client_destroy(c);
            return CREATE_BLOB;
        }
    }
    else {
        flb_plg_error(ctx->ins, "cannot upload %s content to blob (http_status=%i)",
                      ref_name, c->resp.status);
    }
    flb_http_client_destroy(c);

    return FLB_RETRY;
}

static int send_blob(struct flb_config *config,
                     struct flb_input_instance *i_ins,
                     struct flb_azure_blob *ctx,
                     int event_type,
                     int blob_type, char *name, uint64_t part_id,
                     char *tag, int tag_len, void *data, size_t bytes)
{
    int ret;
    uint64_t ms = 0;
    flb_sds_t uri = NULL;
    flb_sds_t block_id = NULL;
    flb_sds_t ref_name = NULL;
    void *payload_buf = data;
    size_t payload_size = bytes;

    ref_name = flb_sds_create_size(256);
    if (!ref_name) {
        return FLB_RETRY;
    }

    if (blob_type == AZURE_BLOB_APPENDBLOB) {
        uri = azb_append_blob_uri(ctx, tag);
    }
    else if (blob_type == AZURE_BLOB_BLOCKBLOB) {
        if (event_type == FLB_EVENT_TYPE_LOGS) {
            block_id = azb_block_blob_id_logs(&ms);
            if (!block_id) {
                flb_plg_error(ctx->ins, "could not generate block id");

                cfl_sds_destroy(ref_name);

                return FLB_RETRY;
            }
            uri = azb_block_blob_uri(ctx, tag, block_id, ms);
            ref_name = flb_sds_printf(&ref_name, "file=%s.%" PRIu64, name, ms);
        }
#ifdef FLB_HAVE_SQLDB
        else if (event_type == FLB_EVENT_TYPE_BLOBS) {
            block_id = azb_block_blob_id_blob(ctx, name, part_id);
            uri = azb_block_blob_uri(ctx, name, block_id, 0);
            ref_name = flb_sds_printf(&ref_name, "file=%s:%" PRIu64, name, part_id);
        }
#endif
    }

    if (!uri) {
        if (block_id != NULL) {
            flb_free(block_id);
        }

        flb_sds_destroy(ref_name);

        return FLB_RETRY;
    }

    /* Logs: Format the data (msgpack -> JSON) */
    if (event_type == FLB_EVENT_TYPE_LOGS) {
        ret = azure_blob_format(config, i_ins,
                                ctx, NULL,
                                FLB_EVENT_TYPE_LOGS,
                                tag, tag_len,
                                data, bytes,
                                &payload_buf, &payload_size);
        if (ret != 0) {
            flb_sds_destroy(uri);

            if (block_id != NULL) {
                flb_free(block_id);
            }

            flb_sds_destroy(ref_name);
            return FLB_ERROR;
        }
    }
#ifdef FLB_HAVE_SQLDB
    else if (event_type == FLB_EVENT_TYPE_BLOBS) {
        payload_buf = data;
        payload_size = bytes;
    }
#endif

    ret = http_send_blob(config, ctx, ref_name, uri, block_id, event_type, payload_buf, payload_size);
    flb_plg_debug(ctx->ins, "http_send_blob()=%i", ret);

    if (ret == FLB_OK) {
        /* For Logs type, we need to commit the block right away */
        if (event_type == FLB_EVENT_TYPE_LOGS) {
            ret = azb_block_blob_commit_block(ctx, block_id, tag, ms);
        }
    }
    else if (ret == CREATE_BLOB) {
        ret = create_blob(ctx, name);
        if (ret == FLB_OK) {
            ret = http_send_blob(config, ctx, ref_name, uri, block_id, event_type, payload_buf, payload_size);
        }
    }
    flb_sds_destroy(ref_name);

    if (payload_buf != data) {
        flb_sds_destroy(payload_buf);
    }

    flb_sds_destroy(uri);

    if (block_id != NULL) {
        flb_free(block_id);
    }

    return ret;
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
 * could not be created, it returns FLB_FALSE.
 * If auto_create_container is disabled, it will return FLB_TRUE assuming the container
 * already exists.
 */
static int ensure_container(struct flb_azure_blob *ctx)
{
    int ret;
    int status;
    size_t b_sent;
    flb_sds_t uri;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    if (!ctx->auto_create_container) {
        flb_plg_info(ctx->ins, "auto_create_container is disabled, assuming container '%s' already exists",
                     ctx->container_name);
        return FLB_TRUE;
    }

    uri = azb_uri_ensure_or_create_container(ctx);
    if (!uri) {
        flb_plg_error(ctx->ins, "cannot create container URI");
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
        flb_plg_info(ctx->ins, "container '%s' already exists", ctx->container_name);
        return FLB_TRUE;
    }
    else if (status == 403) {
        flb_plg_error(ctx->ins, "failed getting container '%s', access denied",
                      ctx->container_name);
        return FLB_FALSE;
    }

    flb_plg_error(ctx->ins, "get container request failed, status=%i",
                  status);

    return FLB_FALSE;
}

static int cb_azure_blob_init(struct flb_output_instance *ins,
                              struct flb_config *config, void *data)
{
    struct flb_azure_blob *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    FLB_TLS_INIT(worker_info);

    ctx = flb_azure_blob_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    flb_output_set_http_debug_callbacks(ins);
    return 0;
}

#ifdef FLB_HAVE_SQLDB
static int blob_chunk_register_parts(struct flb_azure_blob *ctx, uint64_t file_id, size_t total_size)
{
    int ret;
    int64_t parts = 0;
    int64_t id;
    size_t offset_start = 0;
    size_t offset_end = 0;

    /* generate file parts */
    while (offset_start < total_size) {
        offset_end = offset_start + ctx->part_size;

        /* do not exceed maximum size */
        if (offset_end > total_size) {
            offset_end = total_size;
        }

        /* insert part */
        ret = azb_db_file_part_insert(ctx, file_id, parts, offset_start, offset_end, &id);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot insert blob file part into database");
            return -1;
        }
        offset_start = offset_end;
        parts++;
    }

    return parts;
}

static int process_blob_chunk(struct flb_azure_blob *ctx, struct flb_event_chunk *event_chunk)
{
    int64_t ret;
    int64_t file_id;
    cfl_sds_t file_path = NULL;
    cfl_sds_t source = NULL;
    size_t file_size;
    msgpack_object map;

    struct flb_log_event_decoder log_decoder;
    struct flb_log_event         log_event;

    if (ctx->db == NULL) {
        flb_plg_error(ctx->ins, "Cannot process blob because this operation requires a database.");

        return -1;
    }

    ret = flb_log_event_decoder_init(&log_decoder,
                                    (char *) event_chunk->data,
                                     event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                    "Log event decoder initialization error : %i", (int) ret);
        return -1;

    }

    while (flb_log_event_decoder_next(&log_decoder, &log_event) == FLB_EVENT_DECODER_SUCCESS) {
        map = *log_event.body;
        ret = flb_input_blob_file_get_info(map, &source, &file_path, &file_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot get file info from blob record, skipping");
            continue;
        }

        ret = azb_db_file_insert(ctx, source, ctx->real_endpoint, file_path, file_size);

        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot insert blob file into database: %s (size=%lu)",
                          file_path, file_size);
            cfl_sds_destroy(file_path);
            cfl_sds_destroy(source);
            continue;
        }
        cfl_sds_destroy(file_path);
        cfl_sds_destroy(source);

        /* generate the parts by using the newest id created (ret) */
        file_id = ret;
        ret = blob_chunk_register_parts(ctx, file_id, file_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot register blob file '%s 'parts into database",
                            file_path);
            return -1;
        }

        flb_plg_debug(ctx->ins, "blob file '%s' (id=%zu) registered with %zu parts",
                      file_path, file_id, ret);
    }

    flb_log_event_decoder_destroy(&log_decoder);
    return 0;
}

static void cb_azb_blob_file_upload(struct flb_config *config, void *out_context)
{
    int ret;
    char *out_buf = NULL;
    size_t out_size;
    uint64_t id;
    uint64_t file_id;
    uint64_t part_id;
    uint64_t part_delivery_attempts;
    uint64_t file_delivery_attempts;
    off_t offset_start;
    off_t offset_end;
    cfl_sds_t file_destination = NULL;
    cfl_sds_t file_path = NULL;
    cfl_sds_t part_ids = NULL;
    cfl_sds_t source = NULL;
    struct flb_azure_blob *ctx = out_context;
    struct worker_info *info;
    struct flb_blob_delivery_notification *notification;

    info = FLB_TLS_GET(worker_info);

    if (info->active_upload) {
        flb_plg_trace(ctx->ins, "[worker: file upload] upload already in progress...");
        flb_sched_timer_cb_coro_return();
    }

    if (ctx->db == NULL) {
        flb_sched_timer_cb_coro_return();
    }

    info->active_upload = FLB_TRUE;

    /*
     * Check if is there any file which has been fully uploaded and we need to commit it with
     * the Put Block List operation
     */

    pthread_mutex_lock(&ctx->file_upload_commit_file_parts);

    while (1) {
        ret = azb_db_file_get_next_stale(ctx,
                                         &file_id,
                                         &file_path);

        if (ret == 1) {
            delete_blob(ctx, file_path);

            azb_db_file_reset_upload_states(ctx, file_id, file_path);
            azb_db_file_set_aborted_state(ctx, file_id, file_path, 0);

            cfl_sds_destroy(file_path);

            file_path = NULL;
        }
        else {
            break;
        }
    }

    while (1) {
        ret = azb_db_file_get_next_aborted(ctx,
                                           &file_id,
                                           &file_delivery_attempts,
                                           &file_path,
                                           &source);

        if (ret == 1) {
            ret = delete_blob(ctx, file_path);

            if (ctx->file_delivery_attempt_limit != FLB_OUT_RETRY_UNLIMITED &&
                file_delivery_attempts < ctx->file_delivery_attempt_limit) {
                azb_db_file_reset_upload_states(ctx, file_id, file_path);
                azb_db_file_set_aborted_state(ctx, file_id, file_path, 0);
            }
            else {
                ret = azb_db_file_delete(ctx, file_id, file_path);

                notification = flb_calloc(1,
                                        sizeof(
                                            struct flb_blob_delivery_notification));

                if (notification != NULL) {
                    notification->base.dynamically_allocated = FLB_TRUE;
                    notification->base.notification_type = FLB_NOTIFICATION_TYPE_BLOB_DELIVERY;
                    notification->base.destructor = flb_input_blob_delivery_notification_destroy;
                    notification->success = FLB_FALSE;
                    notification->path = cfl_sds_create(file_path);

                    ret = flb_notification_enqueue(FLB_PLUGIN_INPUT,
                                                source,
                                                &notification->base,
                                                config);

                    if (ret != 0) {
                        flb_plg_error(ctx->ins,
                                    "blob file '%s' (id=%" PRIu64 ") notification " \
                                    "delivery error %d", file_path, file_id, ret);

                        flb_notification_cleanup(&notification->base);
                    }
                }
            }

            cfl_sds_destroy(file_path);
            cfl_sds_destroy(source);

            file_path = NULL;
            source = NULL;
        }
        else {
            break;
        }
    }

    ret = azb_db_file_oldest_ready(ctx, &file_id, &file_path, &part_ids, &source);
    if (ret == 0) {
        flb_plg_trace(ctx->ins, "no blob files ready to commit");
    }
    else if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot get oldest blob file ready to upload");
    }
    else if (ret == 1) {
        /* one file is ready to be committed */
        flb_plg_debug(ctx->ins, "blob file '%s' (id=%" PRIu64 ") ready to upload", file_path, file_id);
        ret = azb_block_blob_commit_file_parts(ctx, file_id, file_path, part_ids);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot commit blob file parts for file id=%" PRIu64 " path=%s",
                          file_id, file_path);
        }
        else {
            flb_plg_info(ctx->ins, "blob file '%s' (id=%" PRIu64 ") committed successfully", file_path, file_id);
            /* notify the engine the blob file has been processed */
            /* FIXME! */

            notification = flb_calloc(1,
                                    sizeof(
                                        struct flb_blob_delivery_notification));

            if (notification != NULL) {
                notification->base.dynamically_allocated = FLB_TRUE;
                notification->base.notification_type = FLB_NOTIFICATION_TYPE_BLOB_DELIVERY;
                notification->base.destructor = flb_input_blob_delivery_notification_destroy;
                notification->success = FLB_TRUE;
                notification->path = cfl_sds_create(file_path);

                ret = flb_notification_enqueue(FLB_PLUGIN_INPUT,
                                               source,
                                               &notification->base,
                                               config);

                if (ret != 0) {
                    flb_plg_error(ctx->ins,
                                "blob file '%s' (id=%" PRIu64 ") notification " \
                                "delivery error %d", file_path, file_id, ret);

                    flb_notification_cleanup(&notification->base);
                }
            }

            /* remove the file entry from the database */
            ret = azb_db_file_delete(ctx, file_id, file_path);
            if (ret == -1) {
                flb_plg_error(ctx->ins, "cannot delete blob file '%s' (id=%" PRIu64 ") from the database",
                              file_path, file_id);
            }
        }
    }
    pthread_mutex_unlock(&ctx->file_upload_commit_file_parts);

    if (file_path) {
        cfl_sds_destroy(file_path);
    }
    if (part_ids) {
        cfl_sds_destroy(part_ids);
    }
    if (source) {
        cfl_sds_destroy(source);
    }

    /* check for a next part file and lock it */
    ret = azb_db_file_part_get_next(ctx, &id, &file_id, &part_id,
                                    &offset_start, &offset_end,
                                    &part_delivery_attempts,
                                    &file_delivery_attempts,
                                    &file_path,
                                    &file_destination);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot get next blob file part");
        info->active_upload = FLB_FALSE;
        flb_sched_timer_cb_coro_return();
    }
    else if (ret == 0) {
        flb_plg_trace(ctx->ins, "no more blob file parts to process");
        info->active_upload = FLB_FALSE;
        flb_sched_timer_cb_coro_return();
    }
    else if (ret == 1) {
        /* just continue, the row info was retrieved */
    }


    if (strcmp(file_destination, ctx->real_endpoint) != 0) {
        flb_plg_info(ctx->ins,
                     "endpoint change detected, restarting file : %s\n%s\n%s",
                     file_path,
                     file_destination,
                     ctx->real_endpoint);

        info->active_upload = FLB_FALSE;

        /* we need to set the aborted state flag to wait for existing uploads
         * to finish and then wipe the slate and start again but we don't want
         * to increment the failure count in this case.
         */
        azb_db_file_set_aborted_state(ctx, file_id, file_path, 1);

        cfl_sds_destroy(file_path);
        cfl_sds_destroy(file_destination);

        flb_sched_timer_cb_coro_return();
    }

    /* since this is the first part we want to increment the files
     * delivery attempt counter.
     */
    if (part_id == 0) {
        ret = azb_db_file_delivery_attempts(ctx, file_id, ++file_delivery_attempts);
    }

    /* read the file content */
    ret = flb_utils_read_file_offset(file_path, offset_start, offset_end, &out_buf, &out_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot read file part %s", file_path);

        info->active_upload = FLB_FALSE;

        cfl_sds_destroy(file_path);
        cfl_sds_destroy(file_destination);

        flb_sched_timer_cb_coro_return();
    }

    azb_db_file_part_delivery_attempts(ctx, file_id, part_id, ++part_delivery_attempts);

    flb_plg_debug(ctx->ins, "sending part file %s (id=%" PRIu64 " part_id=%" PRIu64 ")", file_path, id, part_id);

    ret = send_blob(config, NULL, ctx, FLB_EVENT_TYPE_BLOBS,
                    AZURE_BLOB_BLOCKBLOB, file_path, part_id, NULL, 0, out_buf, out_size);

    if (ret == FLB_OK) {
        ret = azb_db_file_part_uploaded(ctx, id);

        if (ret == -1) {
            info->active_upload = FLB_FALSE;

            cfl_sds_destroy(file_path);
            cfl_sds_destroy(file_destination);

            flb_sched_timer_cb_coro_return();
        }
    }
    else if (ret == FLB_RETRY) {
        azb_db_file_part_in_progress(ctx, 0, id);

        if (ctx->part_delivery_attempt_limit != FLB_OUT_RETRY_UNLIMITED &&
            part_delivery_attempts >= ctx->part_delivery_attempt_limit) {
            azb_db_file_set_aborted_state(ctx, file_id, file_path, 1);
        }
    }

    info->active_upload = FLB_FALSE;

    if (out_buf) {
        flb_free(out_buf);
    }

    cfl_sds_destroy(file_path);
    cfl_sds_destroy(file_destination);

    flb_sched_timer_cb_coro_return();
}

static int azb_timer_create(struct flb_azure_blob *ctx)
{
    int ret;
    int64_t ms;
    struct flb_sched *sched;

    sched = flb_sched_ctx_get();

    /* convert from seconds to milliseconds (scheduler needs ms) */
    ms = ctx->upload_parts_timeout * 1000;

    ret = flb_sched_timer_coro_cb_create(sched, FLB_SCHED_TIMER_CB_PERM, ms,
                                         cb_azb_blob_file_upload, ctx, NULL);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to create upload timer");
        return -1;
    }

    return 0;
}
#endif

static void cb_azure_blob_flush(struct flb_event_chunk *event_chunk,
                                struct flb_output_flush *out_flush,
                                struct flb_input_instance *i_ins,
                                void *out_context,
                                struct flb_config *config)
{
    int ret = FLB_OK;
    struct flb_azure_blob *ctx = out_context;
    (void) i_ins;
    (void) config;

    /*
     * Azure blob requires a container. The following function validate that the container exists,
     * otherwise it will be created. Note that that container name is specified by the user
     * in the configuration file.
     *
     * https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-container-create#about-container-naming
     */
    ret = ensure_container(ctx);
    if (ret == FLB_FALSE) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    if (event_chunk->type == FLB_EVENT_TYPE_LOGS) {
        ret = send_blob(config, i_ins, ctx,
                        FLB_EVENT_TYPE_LOGS,
                        ctx->btype, /* blob type per user configuration  */
                        (char *) event_chunk->tag,  /* use tag as 'name' */
                        0,  /* part id */
                        (char *) event_chunk->tag, flb_sds_len(event_chunk->tag),
                        (char *) event_chunk->data, event_chunk->size);

        if (ret == CREATE_BLOB) {
            ret = create_blob(ctx, event_chunk->tag);
            if (ret == FLB_OK) {
                ret = send_blob(config, i_ins, ctx,
                                FLB_EVENT_TYPE_LOGS,
                                ctx->btype, /* blob type per user configuration  */
                                (char *) event_chunk->tag,  /* use tag as 'name' */
                                0,  /* part id */
                                (char *) event_chunk->tag,  /* use tag as 'name' */
                                flb_sds_len(event_chunk->tag),
                                (char *) event_chunk->data, event_chunk->size);
            }
        }
    }
#ifdef FLB_HAVE_SQLDB
    else if (event_chunk->type == FLB_EVENT_TYPE_BLOBS) {
        /*
         * For Blob types, we use the flush callback to enqueue the file, then cb_azb_blob_file_upload()
         * takes care of the rest like reading the file and uploading it to Azure.
         */
        ret = process_blob_chunk(ctx, event_chunk);
        if (ret == -1) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }
#endif

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

/* worker initialization, used for our internal timers */
static int cb_worker_init(void *data, struct flb_config *config)
{
    int ret;
    struct worker_info *info;
    struct flb_azure_blob *ctx = data;

    flb_plg_info(ctx->ins, "initializing worker");

    info = FLB_TLS_GET(worker_info);
    if (!info) {
        /* initialize worker global info */
        info = flb_malloc(sizeof(struct worker_info));
        if (!info) {
            flb_errno();
            return -1;
        }
        info->active_upload = FLB_FALSE;
        FLB_TLS_SET(worker_info, info);
    }

#ifdef FLB_HAVE_SQLDB
    ret = azb_timer_create(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to create upload timer");
        return -1;
    }
#endif

    return 0;
}

/* worker teardown */
static int cb_worker_exit(void *data, struct flb_config *config)
{
    struct worker_info *info;
    struct flb_azure_blob *ctx = data;

    flb_plg_info(ctx->ins, "initializing worker");

    info = FLB_TLS_GET(worker_info);
    if (info != NULL) {
        flb_free(info);
        FLB_TLS_SET(worker_info, NULL);
    }

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

    {
     FLB_CONFIG_MAP_STR, "auth_type", "key",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, auth_type),
     "Set the auth type: key or sas"
    },

    {
     FLB_CONFIG_MAP_STR, "sas_token", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, sas_token),
     "Azure Blob SAS token"
    },

    {
     FLB_CONFIG_MAP_STR, "database_file", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, database_file),
     "Absolute path to a database file to be used to store blob files contexts"
    },

    {
     FLB_CONFIG_MAP_SIZE, "part_size", "25M",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, part_size),
     "Size of each part when uploading blob files"
    },

    {
     FLB_CONFIG_MAP_INT, "file_delivery_attempt_limit", "1",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, file_delivery_attempt_limit),
     "File delivery attempt limit"
    },

    {
     FLB_CONFIG_MAP_INT, "part_delivery_attempt_limit", "1",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, part_delivery_attempt_limit),
     "File part delivery attempt limit"
    },

    {
     FLB_CONFIG_MAP_TIME, "upload_parts_timeout", "10M",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, upload_parts_timeout),
     "Timeout to upload parts of a blob file"
    },

    {
     FLB_CONFIG_MAP_TIME, "upload_part_freshness_limit", "6D",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, upload_parts_freshness_threshold),
     "Maximum lifespan of an uncommitted file part"
    },

    {
     FLB_CONFIG_MAP_STR, "configuration_endpoint_url", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, configuration_endpoint_url),
     "Configuration endpoint URL"
    },

    {
     FLB_CONFIG_MAP_STR, "configuration_endpoint_username", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, configuration_endpoint_username),
     "Configuration endpoint basic authentication username"
    },

    {
     FLB_CONFIG_MAP_STR, "configuration_endpoint_password", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, configuration_endpoint_password),
     "Configuration endpoint basic authentication password"
    },

    {
     FLB_CONFIG_MAP_STR, "configuration_endpoint_bearer_token", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, configuration_endpoint_bearer_token),
     "Configuration endpoint bearer token"
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_azure_blob_plugin = {
    .name           = "azure_blob",
    .description    = "Azure Blob Storage",
    .cb_init        = cb_azure_blob_init,
    .cb_flush       = cb_azure_blob_flush,
    .cb_exit        = cb_azure_blob_exit,
    .cb_worker_init = cb_worker_init,
    .cb_worker_exit = cb_worker_exit,

    /* Test */
    .test_formatter.callback = azure_blob_format,

    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_BLOBS,
    .config_map   = config_map,
    .workers      = 1,
};
