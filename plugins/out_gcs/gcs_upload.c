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
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_uuid.h>

#include "gcs.h"

/* Create a new file for buffering data */
struct gcs_file *gcs_file_create(struct flb_gcs *ctx, const char *tag,
                                 time_t timestamp)
{
    struct gcs_file *file;
    char tmp_name[256];
    flb_sds_t object_key;

    /* Create file structure */
    file = flb_calloc(1, sizeof(struct gcs_file));
    if (!file) {
        flb_errno();
        return NULL;
    }

    /* Generate object key */
    object_key = gcs_format_object_key(ctx, tag, timestamp);
    if (!object_key) {
        flb_plg_error(ctx->ins, "Failed to format object key");
        flb_free(file);
        return NULL;
    }

    /* Generate unique temporary filename */
    snprintf(tmp_name, sizeof(tmp_name), "gcs_%s_%ld_%d.tmp",
             tag ? tag : "notag", timestamp, rand());

    /* Initialize file properties */
    file->create_time = timestamp;
    file->first_log_time = timestamp;
    file->format = ctx->format;
    file->compression = ctx->compression;
    file->object_key = object_key;
    file->tag = flb_sds_create(tag ? tag : "");
    file->locked = FLB_FALSE;
    file->failures = 0;
    file->size = 0;

    /* Create file in store if configured */
    if (ctx->fs && ctx->stream_active) {
        file->fsf = flb_fstore_file_create(ctx->fs, ctx->stream_active,
                                          tmp_name, 0);
        if (!file->fsf) {
            flb_plg_error(ctx->ins, "Failed to create file in store");
            gcs_file_destroy(file);
            return NULL;
        }
        file->file_path = flb_sds_create(tmp_name);
    }

    mk_list_add(&file->_head, &ctx->files);

    flb_plg_debug(ctx->ins, "Created new file: %s -> %s", 
                  tmp_name, object_key);

    return file;
}

/* Write data to file */
int gcs_file_write(struct flb_gcs *ctx, struct gcs_file *file,
                   const char *data, size_t size)
{
    int ret;

    if (!file || file->locked) {
        return -1;
    }

    /* Write to file store */
    if (file->fsf) {
        ret = flb_fstore_file_append(file->fsf, data, size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to write to file store");
            return -1;
        }
    }

    file->size += size;

    /* Update context buffer size */
    ctx->current_buffer_size += size;

    flb_plg_debug(ctx->ins, "Wrote %zu bytes to file %s (total: %zu)",
                  size, file->object_key, file->size);

    return 0;
}

/* Close and prepare file for upload */
int gcs_file_close(struct flb_gcs *ctx, struct gcs_file *file)
{
    if (!file || file->locked) {
        return -1;
    }

    file->locked = FLB_TRUE;

    /* Sync file store */
    if (file->fsf) {
        flb_fstore_file_sync(file->fsf);
    }

    flb_plg_debug(ctx->ins, "Closed file %s (%zu bytes)",
                  file->object_key, file->size);

    return 0;
}

/* Destroy file and cleanup resources */
void gcs_file_destroy(struct gcs_file *file)
{
    if (!file) {
        return;
    }

    /* Remove from list */
    mk_list_del(&file->_head);

    /* Cleanup file store */
    if (file->fsf) {
        flb_fstore_file_delete(file->fsf);
    }

    /* Free strings */
    if (file->object_key) {
        flb_sds_destroy(file->object_key);
    }
    if (file->tag) {
        flb_sds_destroy(file->tag);
    }
    if (file->file_path) {
        flb_sds_destroy(file->file_path);
    }

    flb_free(file);
}

/* Compress data using gzip */
int gcs_compress_data(struct flb_gcs *ctx, const char *data, size_t size,
                      char **out_data, size_t *out_size)
{
    int ret;

    if (ctx->compression != FLB_GCS_COMPRESSION_GZIP) {
        *out_data = (char *) data;
        *out_size = size;
        return 0;
    }

    ret = flb_gzip_compress((void *) data, size, (void **) out_data, out_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to compress data");
        return -1;
    }

    flb_plg_debug(ctx->ins, "Compressed %zu bytes to %zu bytes (%.1f%% reduction)",
                  size, *out_size, 100.0 * (1.0 - (double)*out_size / size));

    return 1; /* Indicates data was allocated and needs to be freed */
}

/* Simple PUT object upload for small files */
static int gcs_upload_put_object(struct flb_gcs *ctx, struct gcs_file *file)
{
    struct flb_http_client *c = NULL;
    struct flb_upstream_conn *u_conn = NULL;
    flb_sds_t uri = NULL;
    flb_sds_t token = NULL;
    char *file_data = NULL;
    size_t file_size;
    char *upload_data = NULL;
    size_t upload_size;
    int compressed = 0;
    int ret = -1;

    /* Read file data */
    if (file->fsf) {
        ret = flb_fstore_file_content_copy(ctx->fs, file->fsf,
                                          (void **) &file_data, &file_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to read file content");
            return -1;
        }
    }
    else {
        flb_plg_error(ctx->ins, "No file content available");
        return -1;
    }

    /* Compress data if needed */
    compressed = gcs_compress_data(ctx, file_data, file_size,
                                  &upload_data, &upload_size);
    if (compressed == -1) {
        goto cleanup;
    }

    /* Get access token */
    token = gcs_oauth2_get_token(ctx);
    if (!token) {
        flb_plg_error(ctx->ins, "Failed to get access token");
        goto cleanup;
    }

    /* Build upload URI */
    uri = flb_sds_create_size(256 + strlen(ctx->bucket) + 
                             flb_sds_len(file->object_key));
    if (!uri) {
        goto cleanup;
    }
    
    uri = flb_sds_printf(&uri, "/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
                        ctx->bucket, file->object_key);

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "Failed to get upstream connection");
        goto cleanup;
    }

    /* Create HTTP client */
    c = flb_http_client(ctx->u, FLB_HTTP_POST, uri,
                       upload_data, upload_size,
                       NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "Failed to create HTTP client");
        goto cleanup;
    }

    /* Add headers */
    flb_http_add_header(c, "Authorization", 13,
                       token, flb_sds_len(token));
    flb_http_add_header(c, "Content-Type", 12,
                       gcs_get_content_type(ctx), 
                       strlen(gcs_get_content_type(ctx)));
    
    if (compressed > 0) {
        flb_http_add_header(c, "Content-Encoding", 16, "gzip", 4);
    }

    /* Send request */
    ret = flb_http_do(c, &u_conn);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to upload file");
        goto cleanup;
    }

    /* Check response */
    if (c->resp.status == 200 || c->resp.status == 201) {
        flb_plg_info(ctx->ins, "Successfully uploaded %s (%zu bytes)",
                     file->object_key, file->size);
        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "Upload failed with status %d: %.*s",
                      c->resp.status, (int)c->resp.payload_size, c->resp.payload);
        ret = -1;
    }

cleanup:
    if (file_data) flb_free(file_data);
    if (compressed > 0 && upload_data) flb_free(upload_data);
    if (uri) flb_sds_destroy(uri);
    if (token) flb_sds_destroy(token);
    if (c) flb_http_client_destroy(c);
    if (u_conn) flb_upstream_conn_release(u_conn);

    return ret;
}

/* Initialize resumable upload session */
int gcs_upload_resumable_init(struct flb_gcs *ctx, struct gcs_upload *upload)
{
    struct flb_http_client *c = NULL;
    struct flb_upstream_conn *u_conn = NULL;
    flb_sds_t uri = NULL;
    flb_sds_t token = NULL;
    flb_sds_t metadata = NULL;
    char *location_header;
    int ret = -1;

    /* Get access token */
    token = gcs_oauth2_get_token(ctx);
    if (!token) {
        flb_plg_error(ctx->ins, "Failed to get access token");
        return -1;
    }

    /* Build upload URI */
    uri = flb_sds_create_size(256 + strlen(ctx->bucket));
    if (!uri) {
        goto cleanup;
    }
    
    uri = flb_sds_printf(&uri, "/upload/storage/v1/b/%s/o?uploadType=resumable",
                        ctx->bucket);

    /* Create metadata JSON */
    metadata = flb_sds_create_size(256 + flb_sds_len(upload->object_key));
    if (!metadata) {
        goto cleanup;
    }
    
    metadata = flb_sds_printf(&metadata,
                             "{"
                             "\"name\":\"%s\","
                             "\"contentType\":\"%s\""
                             "}",
                             upload->object_key,
                             gcs_get_content_type(ctx));

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "Failed to get upstream connection");
        goto cleanup;
    }

    /* Create HTTP client */
    c = flb_http_client(ctx->u, FLB_HTTP_POST, uri,
                       metadata, flb_sds_len(metadata),
                       NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "Failed to create HTTP client");
        goto cleanup;
    }

    /* Add headers */
    flb_http_add_header(c, "Authorization", 13,
                       token, flb_sds_len(token));
    flb_http_add_header(c, "Content-Type", 12,
                       "application/json", 16);
    flb_http_add_header(c, "X-Upload-Content-Type", 21,
                       gcs_get_content_type(ctx),
                       strlen(gcs_get_content_type(ctx)));

    /* Send request */
    ret = flb_http_do(c, &u_conn);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to initialize resumable upload");
        goto cleanup;
    }

    /* Check response and get session URI */
    if (c->resp.status == 200 || c->resp.status == 201) {
        location_header = flb_http_get_header(c, "Location", 8);
        if (location_header) {
            if (upload->session_uri) {
                flb_sds_destroy(upload->session_uri);
            }
            upload->session_uri = flb_sds_create(location_header);
            upload->upload_state = FLB_GCS_UPLOAD_STATE_ACTIVE;
            
            flb_plg_debug(ctx->ins, "Resumable upload initialized: %s",
                         upload->session_uri);
            ret = 0;
        }
        else {
            flb_plg_error(ctx->ins, "No Location header in resumable upload response");
            ret = -1;
        }
    }
    else {
        flb_plg_error(ctx->ins, "Resumable upload init failed with status %d: %.*s",
                      c->resp.status, (int)c->resp.payload_size, c->resp.payload);
        ret = -1;
    }

cleanup:
    if (uri) flb_sds_destroy(uri);
    if (token) flb_sds_destroy(token);
    if (metadata) flb_sds_destroy(metadata);
    if (c) flb_http_client_destroy(c);
    if (u_conn) flb_upstream_conn_release(u_conn);

    return ret;
}

/* Upload a chunk using resumable upload */
int gcs_upload_resumable_chunk(struct flb_gcs *ctx, struct gcs_upload *upload,
                               const char *data, size_t size)
{
    struct flb_http_client *c = NULL;
    struct flb_upstream_conn *u_conn = NULL;
    flb_sds_t token = NULL;
    char content_range[128];
    int ret = -1;

    if (!upload->session_uri || upload->upload_state != FLB_GCS_UPLOAD_STATE_ACTIVE) {
        flb_plg_error(ctx->ins, "Invalid upload state for chunk upload");
        return -1;
    }

    /* Get access token */
    token = gcs_oauth2_get_token(ctx);
    if (!token) {
        flb_plg_error(ctx->ins, "Failed to get access token");
        return -1;
    }

    /* Build content range header */
    snprintf(content_range, sizeof(content_range),
             "bytes %zu-%zu/%zu",
             upload->bytes_uploaded,
             upload->bytes_uploaded + size - 1,
             upload->total_size);

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "Failed to get upstream connection");
        goto cleanup;
    }

    /* Create HTTP client for session URI */
    c = flb_http_client(ctx->u, FLB_HTTP_PUT, upload->session_uri,
                       data, size, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "Failed to create HTTP client");
        goto cleanup;
    }

    /* Add headers */
    flb_http_add_header(c, "Authorization", 13,
                       token, flb_sds_len(token));
    flb_http_add_header(c, "Content-Type", 12,
                       gcs_get_content_type(ctx),
                       strlen(gcs_get_content_type(ctx)));
    flb_http_add_header(c, "Content-Range", 13,
                       content_range, strlen(content_range));

    /* Send request */
    ret = flb_http_do(c, &u_conn);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to upload chunk");
        goto cleanup;
    }

    /* Check response */
    if (c->resp.status == 200 || c->resp.status == 201) {
        /* Upload complete */
        upload->upload_state = FLB_GCS_UPLOAD_STATE_COMPLETE;
        flb_plg_info(ctx->ins, "Resumable upload completed: %s",
                     upload->object_key);
        ret = 0;
    }
    else if (c->resp.status == 308) {
        /* Partial upload, continue */
        upload->bytes_uploaded += size;
        flb_plg_debug(ctx->ins, "Uploaded chunk %zu bytes (%zu/%zu)",
                     size, upload->bytes_uploaded, upload->total_size);
        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "Chunk upload failed with status %d: %.*s",
                      c->resp.status, (int)c->resp.payload_size, c->resp.payload);
        upload->upload_errors++;
        ret = -1;
    }

cleanup:
    if (token) flb_sds_destroy(token);
    if (c) flb_http_client_destroy(c);
    if (u_conn) flb_upstream_conn_release(u_conn);

    return ret;
}

/* Main file upload function */
int gcs_upload_file(struct flb_gcs *ctx, struct gcs_file *file)
{
    struct gcs_upload *upload;
    int ret;

    if (!file || !file->locked) {
        return -1;
    }

    /* Choose upload method based on file size and configuration */
    if (ctx->use_put_object || file->size < ctx->upload_chunk_size) {
        return gcs_upload_put_object(ctx, file);
    }

    /* Create upload context for resumable upload */
    upload = flb_calloc(1, sizeof(struct gcs_upload));
    if (!upload) {
        flb_errno();
        return -1;
    }

    upload->object_key = flb_sds_create(file->object_key);
    upload->tag = flb_sds_create(file->tag);
    upload->total_size = file->size;
    upload->bytes_uploaded = 0;
    upload->upload_state = FLB_GCS_UPLOAD_STATE_NEW;
    upload->upload_errors = 0;
    upload->retry_count = 0;
    upload->init_time = time(NULL);
    upload->file = file;

    mk_list_add(&upload->_head, &ctx->uploads);

    /* Initialize resumable upload */
    ret = gcs_upload_resumable_init(ctx, upload);
    if (ret == -1) {
        mk_list_del(&upload->_head);
        if (upload->object_key) flb_sds_destroy(upload->object_key);
        if (upload->tag) flb_sds_destroy(upload->tag);
        flb_free(upload);
        return -1;
    }

    /* TODO: Implement chunked upload logic */
    flb_plg_debug(ctx->ins, "Resumable upload ready for file %s",
                  file->object_key);

    return 0;
}