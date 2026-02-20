/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_utils.h>
#include <stdio.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_fstore.h>
#include <msgpack.h>
#include <fluent-bit/flb_version.h>
#include <inttypes.h>

#include "azure_kusto.h"
#include "azure_kusto_conf.h"
#include "azure_kusto_ingest.h"
#include "azure_msiauth.h"
#include "azure_kusto_store.h"

static int azure_kusto_get_msi_token(struct flb_azure_kusto *ctx)
{
    char *token;

    /* Retrieve access token */
    token = flb_azure_msiauth_token_get(ctx->o);
    if (!token) {
        flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
        return -1;
    }

    return 0;
}

static int azure_kusto_get_workload_identity_token(struct flb_azure_kusto *ctx)
{
    int ret;
    
    ret = flb_azure_workload_identity_token_get(ctx->o, 
                                               ctx->workload_identity_token_file,
                                               ctx->client_id, 
                                               ctx->tenant_id);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error retrieving workload identity token");
        return -1;
    }
    
    flb_plg_debug(ctx->ins, "Workload identity token retrieved successfully");
    return 0;
}

static int azure_kusto_get_service_principal_token(struct flb_azure_kusto *ctx)
{
    int ret;
    
    /* Clear any previous oauth2 payload content */
    flb_oauth2_payload_clear(ctx->o);

    ret = flb_oauth2_payload_append(ctx->o, "grant_type", 10, "client_credentials", 18);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o, "scope", 5, FLB_AZURE_KUSTO_SCOPE, 39);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o, "client_id", 9, ctx->client_id, -1);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o, "client_secret", 13, ctx->client_secret, -1);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        return -1;
    }

    /* Retrieve access token */
    char *token = flb_oauth2_token_get(ctx->o);
    if (!token) {
        flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
        return -1;
    }

    flb_plg_debug(ctx->ins, "OAuth2 token retrieval process completed successfully");
    return 0;
}

flb_sds_t get_azure_kusto_token(struct flb_azure_kusto *ctx)
{
    int ret = 0;
    flb_sds_t output = NULL;

    if (pthread_mutex_lock(&ctx->token_mutex)) {
        flb_plg_error(ctx->ins, "error locking mutex");
        return NULL;
    }

    if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
        switch (ctx->auth_type) {
            case FLB_AZURE_KUSTO_AUTH_WORKLOAD_IDENTITY:
                ret = azure_kusto_get_workload_identity_token(ctx);
                break;
            case FLB_AZURE_KUSTO_AUTH_MANAGED_IDENTITY_SYSTEM:
            case FLB_AZURE_KUSTO_AUTH_MANAGED_IDENTITY_USER:
                ret = azure_kusto_get_msi_token(ctx);
                break;
            case FLB_AZURE_KUSTO_AUTH_SERVICE_PRINCIPAL:
            default:
                ret = azure_kusto_get_service_principal_token(ctx);
                break;
        }
    }

    /* Copy string to prevent race conditions (get_oauth2 can free the string) */
    if (ret == 0) {
        output = flb_sds_create_size(flb_sds_len(ctx->o->token_type) +
                                     flb_sds_len(ctx->o->access_token) + 2);
        if (!output) {
            flb_plg_error(ctx->ins, "error creating token buffer");
            return NULL;
        }
        flb_sds_snprintf(&output, flb_sds_alloc(output), "%s %s", ctx->o->token_type,
                         ctx->o->access_token);
    }

    if (pthread_mutex_unlock(&ctx->token_mutex)) {
        flb_plg_error(ctx->ins, "error unlocking mutex");
        if (output) {
            flb_sds_destroy(output);
        }
        return NULL;
    }

    return output;
}

/**
 * Executes a control command against kusto's endpoint
 *
 * @param ctx       Plugin's context
 * @param csl       Kusto's control command
 * @return flb_sds_t      Returns the response or NULL on error.
 */
flb_sds_t execute_ingest_csl_command(struct flb_azure_kusto *ctx, const char *csl)
{
    flb_sds_t token;
    flb_sds_t body;
    size_t b_sent;
    int ret;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    flb_sds_t resp = NULL;

    flb_plg_debug(ctx->ins, "before getting upstream connection");

    flb_plg_debug(ctx->ins, "Logging attributes of flb_azure_kusto_resources:");
    flb_plg_debug(ctx->ins, "blob_ha: %p", ctx->resources->blob_ha);
    flb_plg_debug(ctx->ins, "queue_ha: %p", ctx->resources->queue_ha);
    flb_plg_debug(ctx->ins, "load_time: %" PRIu64, ctx->resources->load_time);

    ctx->u->base.net.connect_timeout = ctx->ingestion_endpoint_connect_timeout;
    if (ctx->buffering_enabled == FLB_TRUE){
        ctx->u->base.flags &= ~(FLB_IO_ASYNC);
    }
    flb_plg_debug(ctx->ins, "execute_ingest_csl_command -- async flag is %d", flb_stream_is_async(&ctx->u->base));

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);

    if (u_conn) {
        token = get_azure_kusto_token(ctx);

        if (token) {
            /* Compose request body */
            body = flb_sds_create_size(sizeof(FLB_AZURE_KUSTO_MGMT_BODY_TEMPLATE) - 1 +
                                       strlen(csl));

            if (body) {
                flb_sds_snprintf(&body, flb_sds_alloc(body),
                                 FLB_AZURE_KUSTO_MGMT_BODY_TEMPLATE, csl);

                /* Compose HTTP Client request */
                c = flb_http_client(u_conn, FLB_HTTP_POST, FLB_AZURE_KUSTO_MGMT_URI_PATH,
                                    body, flb_sds_len(body), NULL, 0, NULL, 0);

                if (c) {
                    /* Add headers */
                    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
                    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
                    flb_http_add_header(c, "Accept", 6, "application/json", 16);
                    flb_http_add_header(c, "Authorization", 13, token,
                                        flb_sds_len(token));
                    flb_http_add_header(c, "x-ms-client-version", 19, FLB_VERSION_STR, strlen(FLB_VERSION_STR));
                    flb_http_add_header(c, "x-ms-app", 8, "Fluent-Bit", 10);
                    flb_http_add_header(c, "x-ms-user", 9, "Fluent-Bit", 10);
                    flb_http_buffer_size(c, FLB_HTTP_DATA_SIZE_MAX * 10);

                    /* Send HTTP request */
                    ret = flb_http_do(c, &b_sent);
                    flb_plg_debug(
                            ctx->ins,
                            "Kusto ingestion command request http_do=%i, HTTP Status: %i",
                            ret, c->resp.status);
                    flb_plg_debug(ctx->ins, "Kusto ingestion command HTTP response payload: %.*s", (int)c->resp.payload_size, c->resp.payload);

                    if (ret == 0) {
                        if (c->resp.status == 200) {
                            /* Copy payload response to the response param */
                            resp = flb_sds_create_len(c->resp.payload, c->resp.payload_size);
                        }
                        else {
                            flb_plg_error(ctx->ins, "Kusto Ingestion Resources Request failed with HTTP Status: %i", c->resp.status);
                            if (c->resp.payload_size > 0) {
                                flb_plg_error(ctx->ins, "Kusto Ingestion Resources Response payload: \n%s", c->resp.payload);
                            }
                        }
                    }
                    else {
                        flb_plg_error(ctx->ins, "Kusto Ingestion Resources :: cannot send HTTP request");
                    }

                    flb_http_client_destroy(c);
                }
                else {
                    flb_plg_error(ctx->ins, "cannot create HTTP client context");
                }

                flb_sds_destroy(body);
            }
            else {
                flb_plg_error(ctx->ins, "cannot construct request body");
            }

            flb_sds_destroy(token);
        }
        else {
            flb_plg_error(ctx->ins, "cannot retrieve oauth2 token");
        }

        flb_upstream_conn_release(u_conn);
    }
    else {
        flb_plg_error(ctx->ins, "cannot create upstream connection");
    }

    return resp;
}

/**
 * construct_request_buffer - Constructs a request buffer for Azure Kusto ingestion.
 *
 * This function is responsible for preparing a data buffer that will be used
 * to send data to Azure Kusto. It handles both new incoming data and data
 * that has been previously buffered in a file. The function performs the
 * following tasks:
 *
 * 1. Validates Input: Checks if both `new_data` and `upload_file` are NULL,
 *    which would indicate an error since there is no data to process.
 *
 * 2. Reads Buffered Data: If an `upload_file` is provided, it reads the
 *    locally buffered data from the file and locks the file to prevent
 *    concurrent modifications.
 *
 * 3. Appends New Data: If `new_data` is provided, it appends this data to
 *    the buffered data, reallocating memory as necessary to accommodate the
 *    combined data size.
 *
 * 4. Outputs the Result: Sets the output parameters `out_buf` and `out_size`
 *    to point to the constructed buffer and its size, respectively.
 *
 * The function ensures that the buffer is correctly terminated if compression
 * is not enabled, and it handles memory allocation and error checking
 * throughout the process.
 *
 * Parameters:
 * @ctx:        The context containing configuration and state information.
 * @new_data:   The new data to be appended to the buffer, if any.
 * @upload_file: The file containing previously buffered data, if any.
 * @out_buf:    Pointer to the output buffer that will be constructed.
 * @out_size:   Pointer to the size of the constructed buffer.
 *
 * Returns:
 * 0 on success, or -1 on failure with an appropriate error message logged.
 */
static int construct_request_buffer(struct flb_azure_kusto *ctx, flb_sds_t new_data,
                                    struct azure_kusto_file *upload_file,
                                    char **out_buf, size_t *out_size)
{
    char *body;
    char *tmp;
    size_t body_size = 0;
    char *buffered_data = NULL;
    size_t buffer_size = 0;
    int ret;

    if (new_data == NULL && upload_file == NULL) {
        flb_plg_error(ctx->ins, "[construct_request_buffer] Something went wrong"
                                " both chunk and new_data are NULL");
        return -1;
    }

    if (upload_file) {
        ret = azure_kusto_store_file_upload_read(ctx, upload_file->fsf, &buffered_data, &buffer_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not read locally buffered data %s",
                          upload_file->fsf->name);
            return -1;
        }

        /*
         * lock the upload_file from buffer list
         */
        azure_kusto_store_file_lock(upload_file);
        body = buffered_data;
        body_size = buffer_size;
    }

    flb_plg_debug(ctx->ins, "[construct_request_buffer] size of buffer file read %zu", buffer_size);

    /*
     * If new data is arriving, increase the original 'buffered_data' size
     * to append the new one.
     */
    if (new_data) {
        body_size += flb_sds_len(new_data);
        flb_plg_debug(ctx->ins, "[construct_request_buffer] size of new_data %zu", body_size);

        tmp = flb_realloc(buffered_data, body_size + 1);
        if (!tmp) {
            flb_errno();
            flb_free(buffered_data);
            if (upload_file) {
                azure_kusto_store_file_unlock(upload_file);
            }
            return -1;
        }
        body = buffered_data = tmp;
        memcpy(body + buffer_size, new_data, flb_sds_len(new_data));
        if (ctx->compression_enabled == FLB_FALSE){
            body[body_size] = '\0';
        }
    }

    flb_plg_debug(ctx->ins, "[construct_request_buffer] final increased %zu", body_size);

    *out_buf = body;
    *out_size = body_size;

    return 0;
}

/**
 * Ingest all data chunks from the file storage streams into Azure Kusto.
 *
 * This function iterates over all file storage streams associated with the
 * given Azure Kusto context. For each
 * file in the stream, it checks if the file (chunk) is locked or has exceeded
 * the maximum number of retry attempts. If the chunk is eligible for processing,
 * it constructs a request buffer from the chunk data, optionally compresses
 * the payload, and attempts to ingest it into Azure Kusto.
 *
 * The function performs the following steps:
 * 1. Iterate over each file storage stream in the context.
 * 2. For each file in the stream, check if it is locked or has exceeded
 *    the maximum retry attempts. If so, skip processing.
 * 3. Construct a request buffer from the chunk data.
 * 4. Create a payload from the buffer and optionally compress it if
 *    compression is enabled.
 * 5. Load the necessary ingestion resources for Azure Kusto.
 * 6. Attempt to ingest the payload into Azure Kusto using queued ingestion.
 * 7. If ingestion is successful, clean up the local buffer file.
 * 8. Handle errors by unlocking the chunk, incrementing failure counts,
 *    and logging appropriate error messages.
 *
 * @param ctx    Pointer to the Azure Kusto context containing configuration
 *               and state information.
 * @param config Pointer to the Fluent Bit configuration structure.
 *
 * @return 0 on success, or -1 on failure.
 */
static int ingest_all_chunks(struct flb_azure_kusto *ctx, struct flb_config *config)
{
    struct azure_kusto_file *chunk;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_file *fsf;
    struct flb_fstore_stream *fs_stream;
    flb_sds_t payload = NULL;
    void *final_payload = NULL;
    size_t final_payload_size = 0;
    char *buffer = NULL;
    size_t buffer_size;
    int ret;
    int is_compressed = FLB_FALSE;
    flb_sds_t tag_sds;

    mk_list_foreach_safe(head, tmp, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        if (fs_stream == ctx->stream_upload) {
            continue;
        }

        mk_list_foreach_safe(f_head, tmp, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            chunk = fsf->data;

            /* Locked chunks are being processed, skip */
            if (chunk->locked == FLB_TRUE) {
                continue;
            }

            if (chunk->failures >= ctx->scheduler_max_retries) {
                flb_plg_warn(ctx->ins,
                             "ingest_all_old_buffer_files :: Chunk for tag %s failed to send %i times, "
                             "will not retry",
                             (char *) fsf->meta_buf, ctx->scheduler_max_retries);
                if (ctx->delete_on_max_upload_error){
                    azure_kusto_store_file_delete(ctx, chunk);
                }
                else{
                    azure_kusto_store_file_inactive(ctx, chunk);
                }
                continue;
            }

            ret = construct_request_buffer(ctx, NULL, chunk,
                                           &buffer, &buffer_size);
            if (ret < 0) {
                flb_plg_error(ctx->ins,
                              "ingest_all_old_buffer_files :: Could not construct request buffer for %s",
                              chunk->file_path);
                return -1;
            }

            payload = flb_sds_create_len(buffer, buffer_size);
            tag_sds = flb_sds_create(fsf->meta_buf);
            flb_free(buffer);

            /* Compress the JSON payload */
            if (ctx->compression_enabled == FLB_TRUE) {
                ret = flb_gzip_compress((void *) payload, flb_sds_len(payload),
                                        &final_payload, &final_payload_size);
                if (ret != 0) {
                    flb_plg_error(ctx->ins,
                                  "ingest_all_old_buffer_files :: cannot gzip payload");
                    flb_sds_destroy(payload);
                    flb_sds_destroy(tag_sds);
                    return -1;
                }
                else {
                    is_compressed = FLB_TRUE;
                    flb_plg_debug(ctx->ins, "ingest_all_old_buffer_files :: enabled payload gzip compression");
                }
            }
            else {
                final_payload = payload;
                final_payload_size = flb_sds_len(payload);
            }

            ret = azure_kusto_load_ingestion_resources(ctx, config);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "ingest_all_old_buffer_files :: cannot load ingestion resources");
                return -1;
            }

            /* Call azure_kusto_queued_ingestion to ingest the payload */
            ret = azure_kusto_queued_ingestion(ctx, tag_sds, flb_sds_len(tag_sds), final_payload, final_payload_size, chunk);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "ingest_all_old_buffer_files :: Failed to ingest data to Azure Kusto");
                if (chunk){
                    azure_kusto_store_file_unlock(chunk);
                    chunk->failures += 1;
                }
                flb_sds_destroy(tag_sds);
                flb_sds_destroy(payload);
                if (is_compressed) {
                    flb_free(final_payload);
                }
                return -1;
            }

            flb_sds_destroy(tag_sds);
            flb_sds_destroy(payload);
            if (is_compressed) {
                flb_free(final_payload);
            }

            /* data was sent successfully- delete the local buffer */
            azure_kusto_store_file_cleanup(ctx, chunk);
        }
    }

    return 0;
}

/**
 * cb_azure_kusto_ingest - Callback function for ingesting data to Azure Kusto.
 *
 * Parameters:
 * @config: Pointer to the Fluent Bit configuration context.
 * @data: Pointer to the Kusto plugin context, which contains configuration and
 *        state information for the ingestion process.
 *
 * The function performs the following steps:
 * 1. Initializes a random seed for staggered refresh intervals.
 * 2. Logs the start of the upload timer callback.
 * 3. Iterates over all files in the active stream.
 * 4. Checks if each file has timed out and skips those that haven't.
 * 5. Skips files that are currently locked.
 * 6. For each eligible file, enters a retry loop to handle ingestion attempts:
 *    a. Constructs the request buffer for the file.
 *    b. Compresses the payload if compression is enabled.
 *    c. Loads necessary ingestion resources.
 *    d. Performs the queued ingestion to Azure Kusto.
 *    e. Deletes the file upon successful ingestion.
 * 7. Implements exponential backoff with jitter for retries.
 * 8. Logs errors and warnings for failed operations and retries.
 * 9. If the maximum number of retries is reached, logs an error and either
 *    deletes or marks the file as inactive based on configuration.
 * 10. Logs the end of the upload timer callback.
 */
static void cb_azure_kusto_ingest(struct flb_config *config, void *data)
{
    struct flb_azure_kusto *ctx = data;
    struct azure_kusto_file *file = NULL;
    struct flb_fstore_file *fsf;
    char *buffer = NULL;
    size_t buffer_size = 0;
    void *final_payload = NULL;
    size_t final_payload_size = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    int ret;
    time_t now;
    flb_sds_t payload;
    flb_sds_t tag_sds;
    int is_compressed = FLB_FALSE;
    int retry_count;
    int backoff_time;
    int max_backoff_time = 64; /* Maximum backoff time in seconds */

    /* Initialize random seed for staggered refresh intervals */
    srand(time(NULL));

    /* Log the start of the upload timer callback */
    flb_plg_debug(ctx->ins, "Running upload timer callback (scheduler_kusto_ingest)..");
    now = time(NULL);

    /* Iterate over all files in the active stream */
    mk_list_foreach_safe(head, tmp, &ctx->stream_active->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        file = fsf->data;
        flb_plg_debug(ctx->ins, "scheduler_kusto_ingest :: Iterating files inside upload timer callback (cb_azure_kusto_ingest).. %s", file->fsf->name);

        /* Check if the file has timed out */
        if (now < (file->create_time + ctx->upload_timeout + ctx->retry_time)) {
            continue; /* Skip files that haven't timed out */
        }

        flb_plg_debug(ctx->ins, "scheduler_kusto_ingest :: Before file locked check %s", file->fsf->name);

        /* Skip locked files */
        if (file->locked == FLB_TRUE) {
            continue;
        }

        retry_count = 0;
        backoff_time = 2; /* Initial backoff time in seconds */

        /* Retry loop for handling retries */
        while (retry_count < ctx->scheduler_max_retries) {
            flb_plg_debug(ctx->ins, "scheduler_kusto_ingest :: Before construct_request_buffer %s", file->fsf->name);

            /* Construct the request buffer */
            ret = construct_request_buffer(ctx, NULL, file, &buffer, &buffer_size);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "scheduler_kusto_ingest :: Could not construct request buffer for %s", file->fsf->name);
                retry_count++;
                /* Add jitter: random value between 0 and backoff_time */
                int jitter = rand() % backoff_time;
                sleep(backoff_time + jitter); /* Exponential backoff with jitter */
                backoff_time = (backoff_time * 2 < max_backoff_time) ? backoff_time * 2 : max_backoff_time; /* Double the backoff time, but cap it */
                continue; /* Retry on failure */
            }

            payload = flb_sds_create_len(buffer, buffer_size);
            tag_sds = flb_sds_create(fsf->meta_buf);

            /* Compress the JSON payload if compression is enabled */
            if (ctx->compression_enabled == FLB_TRUE) {
                ret = flb_gzip_compress((void *) payload, flb_sds_len(payload), &final_payload, &final_payload_size);
                if (ret != 0) {
                    flb_plg_error(ctx->ins, "scheduler_kusto_ingest :: cannot gzip payload");
                    flb_free(buffer);
                    flb_sds_destroy(payload);
                    flb_sds_destroy(tag_sds);
                    retry_count++;
                    if (file){
                        azure_kusto_store_file_unlock(file);
                        file->failures += 1;
                    }
                    /* Add jitter: random value between 0 and backoff_time */
                    int jitter = rand() % backoff_time;
                    flb_plg_warn(ctx->ins, "scheduler_kusto_ingest :: failed while compressing payload :: Retrying in %d seconds (attempt %d of %d) with jitter %d for file %s",
                                 backoff_time + jitter, retry_count, ctx->scheduler_max_retries, jitter, file->fsf->name);
                    sleep(backoff_time + jitter); /* Exponential backoff with jitter */
                    backoff_time = (backoff_time * 2 < max_backoff_time) ? backoff_time * 2 : max_backoff_time; /* Double the backoff time, but cap it */
                    continue; /* Retry on failure */
                }
                else {
                    is_compressed = FLB_TRUE;
                    flb_plg_debug(ctx->ins, "scheduler_kusto_ingest :: enabled payload gzip compression");
                }
            }
            else {
                final_payload = payload;
                final_payload_size = flb_sds_len(payload);
            }

            flb_plg_debug(ctx->ins, "scheduler_kusto_ingest ::: tag of the file %s", tag_sds);

            /* Load ingestion resources */
            ret = azure_kusto_load_ingestion_resources(ctx, config);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "scheduler_kusto_ingest :: cannot load ingestion resources");

                /* Free allocated resources */
                flb_free(buffer);
                flb_sds_destroy(payload);
                flb_sds_destroy(tag_sds);
                if (is_compressed) {
                    flb_free(final_payload);
                }

                retry_count++;
                if (file){
                    azure_kusto_store_file_unlock(file);
                    file->failures += 1;
                }
                /* Add jitter: random value between 0 and backoff_time */
                int jitter = rand() % backoff_time;
                flb_plg_warn(ctx->ins, "scheduler_kusto_ingest :: error loading ingestion resources :: Retrying in %d seconds (attempt %d of %d) with jitter %d for file %s",
                             backoff_time + jitter, retry_count, ctx->scheduler_max_retries, jitter, file->fsf->name);
                sleep(backoff_time + jitter); /* Exponential backoff with jitter */
                backoff_time = (backoff_time * 2 < max_backoff_time) ? backoff_time * 2 : max_backoff_time; /* Double the backoff time, but cap it */
                continue; /* Retry on failure */
            }

            flb_plg_debug(ctx->ins, "scheduler_kusto_ingest ::: before starting kusto queued ingestion %s", file->fsf->name);

            /* Perform the queued ingestion */
            ret = azure_kusto_queued_ingestion(ctx, tag_sds, flb_sds_len(tag_sds), final_payload, final_payload_size, NULL);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "scheduler_kusto_ingest: Failed to ingest data to kusto");

                /* Free allocated resources */
                flb_free(buffer);
                flb_sds_destroy(payload);
                flb_sds_destroy(tag_sds);
                if (is_compressed) {
                    flb_free(final_payload);
                }

                retry_count++;
                if (file){
                    azure_kusto_store_file_unlock(file);
                    file->failures += 1;
                }
                /* Add jitter: random value between 0 and backoff_time */
                int jitter = rand() % backoff_time;
                flb_plg_warn(ctx->ins, "scheduler_kusto_ingest :: error while ingesting to kusto :: Retrying in %d seconds (attempt %d of %d) with jitter %d for file %s",
                             backoff_time + jitter, retry_count, ctx->scheduler_max_retries, jitter, file->fsf->name);
                sleep(backoff_time + jitter); /* Exponential backoff with jitter */
                backoff_time = (backoff_time * 2 < max_backoff_time) ? backoff_time * 2 : max_backoff_time; /* Double the backoff time, but cap it */
                continue; /* Retry on failure */
            }

            /* Delete the file after successful ingestion */
            ret = azure_kusto_store_file_delete(ctx, file);
            if (ret == 0) {
                flb_plg_debug(ctx->ins, "scheduler_kusto_ingest :: deleted successfully ingested file");
            }
            else {
                flb_plg_error(ctx->ins, "scheduler_kusto_ingest :: failed to delete ingested file %s", fsf->name);
                if (file){
                    azure_kusto_store_file_unlock(file);
                    file->failures += 1;
                }
            }

            /* Free allocated resources */
            flb_free(buffer);
            flb_sds_destroy(payload);
            flb_sds_destroy(tag_sds);
            if (is_compressed) {
                flb_free(final_payload);
            }

            /* If all operations succeed, break out of the retry loop */
            break;
        }

        /* If the maximum number of retries is reached, log an error and move to the next file */
        if (retry_count >= ctx->scheduler_max_retries) {
            flb_plg_error(ctx->ins, "scheduler_kusto_ingest :: Max retries reached for file %s", file->fsf->name);
            if (ctx->delete_on_max_upload_error){
                azure_kusto_store_file_delete(ctx, file);
            }
            else {
                azure_kusto_store_file_inactive(ctx, file);
            }
        }
    }
    /* Log the end of the upload timer callback */
    flb_plg_debug(ctx->ins, "Exited upload timer callback (cb_azure_kusto_ingest)..");
}


/**
 * Ingest data to Azure Kusto
 *
 * This function is responsible for preparing and sending data to Azure Kusto for ingestion.
 * It constructs a request buffer from the provided data, optionally compresses the payload,
 * and then sends it to Azure Kusto using a queued ingestion method.
 *
 * Parameters:
 * - out_context: A pointer to the output context, which is expected to be of type `struct flb_azure_kusto`.
 * - new_data: The new data to be ingested, represented as a flexible string descriptor (flb_sds_t).
 * - upload_file: A pointer to an `azure_kusto_file` structure that contains information about the file to be uploaded.
 * - tag: A constant character pointer representing the tag associated with the data.
 * - tag_len: An integer representing the length of the tag.
 *
 * Returns:
 * - 0 on successful ingestion.
 * - -1 if an error occurs during buffer construction, compression, or ingestion.
 *
 * The function performs the following steps:
 * 1. Constructs a request buffer from the provided data and upload file information.
 * 2. Creates a payload from the buffer and frees the buffer memory.
 * 3. Optionally compresses the payload using gzip if compression is enabled in the context.
 * 4. Calls the `azure_kusto_queued_ingestion` function to send the payload to Azure Kusto.
 * 5. Cleans up allocated resources, including destroying the payload and tag strings, and freeing the compressed payload if applicable.
 */
static int ingest_to_kusto(void *out_context, flb_sds_t new_data,
                               struct azure_kusto_file *upload_file,
                               const char *tag, int tag_len)
{
    int ret;
    char *buffer = NULL;
    size_t buffer_size;
    struct flb_azure_kusto *ctx = out_context;
    flb_sds_t payload = NULL;
    void *final_payload = NULL;
    size_t final_payload_size = 0;
    int is_compressed = FLB_FALSE;
    flb_sds_t tag_sds = flb_sds_create_len(tag, tag_len);

    /* Create buffer */
    ret = construct_request_buffer(ctx, new_data, upload_file, &buffer, &buffer_size);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not construct request buffer for %s",
                      upload_file->fsf->name);
        return -1;
    }
    payload = flb_sds_create_len(buffer, buffer_size);
    if (!payload) {
        flb_plg_error(ctx->ins, "Could not create payload SDS");
        flb_free(buffer);
        return -1;
    }
    flb_free(buffer);

    /* Compress the JSON payload */
    if (ctx->compression_enabled == FLB_TRUE) {
        ret = flb_gzip_compress((void *) payload, flb_sds_len(payload),
                                &final_payload, &final_payload_size);
        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "cannot gzip payload");
            flb_sds_destroy(payload);
            flb_sds_destroy(tag_sds);
            return -1;
        }
        else {
            is_compressed = FLB_TRUE;
            flb_plg_debug(ctx->ins, "enabled payload gzip compression");
            /* JSON buffer will be cleared at cleanup: */
        }
    }
    else {
        final_payload = payload;
        final_payload_size = flb_sds_len(payload);
    }

    /* Call azure_kusto_queued_ingestion to ingest the payload */
    ret = azure_kusto_queued_ingestion(ctx, tag_sds, tag_len, final_payload, final_payload_size, upload_file);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "Failed to ingest data to Azure Kusto");
        flb_sds_destroy(tag_sds);
        flb_sds_destroy(payload);
        if (is_compressed) {
            flb_free(final_payload);
        }
        return -1;
    }

    flb_sds_destroy(tag_sds);
    flb_sds_destroy(payload);
    if (is_compressed) {
        flb_free(final_payload);
    }

    return 0;
}

/**
 * Initializes the Azure Kusto output plugin.
 *
 * This function sets up the necessary configurations and resources for the Azure Kusto
 * output plugin to function correctly. It performs the following tasks:
 *
 * 1. Creates a configuration context for the plugin using the provided instance and config.
 * 2. Initializes local storage if buffering is enabled, ensuring that the storage directory
 *    is set up and any existing buffered data is accounted for.
 * 3. Validates the configured file size for uploads, ensuring it meets the minimum and
 *    maximum constraints.
 * 4. Sets up network configurations, including enabling IPv6 if specified.
 * 5. Initializes mutexes for thread-safe operations related to OAuth tokens and resource
 *    management.
 * 6. Creates an upstream context for connecting to the Kusto Ingestion endpoint, configuring
 *    it for synchronous or asynchronous operation based on buffering settings.
 * 7. If IMDS (Instance Metadata Service) is used, creates an upstream context for it.
 * 8. Establishes an OAuth2 context for handling authentication with Azure services.
 * 9. Associates the upstream context with the output instance for data transmission.
 *
 * The function returns 0 on successful initialization or -1 if any step fails.
 *
 * @param ins    The output instance to initialize.
 * @param config The configuration context for Fluent Bit.
 * @param data   Additional data passed to the initialization function.
 *
 * @return 0 on success, -1 on failure.
 */
static int cb_azure_kusto_init(struct flb_output_instance *ins, struct flb_config *config,
                               void *data)
{
    int io_flags = FLB_IO_TLS;
    struct flb_azure_kusto *ctx;

    flb_plg_debug(ins, "inside azure kusto init");

    /* Create config context */
    ctx = flb_azure_kusto_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    if (ctx->buffering_enabled == FLB_TRUE) {
        ctx->ins = ins;
        ctx->retry_time = 0;

        /* Initialize local storage */
        int ret = azure_kusto_store_init(ctx);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to initialize kusto storage: %s",
                          ctx->store_dir);
            return -1;
        }
        ctx->has_old_buffers = azure_kusto_store_has_data(ctx);

        /* validate 'total_file_size' */
        if (ctx->file_size <= 0) {
            flb_plg_error(ctx->ins, "Failed to parse upload_file_size");
            return -1;
        }
        if (ctx->file_size < 1000000) {
            flb_plg_error(ctx->ins, "upload_file_size must be at least 1MB");
            return -1;
        }
        if (ctx->file_size > MAX_FILE_SIZE) {
            flb_plg_error(ctx->ins, "Max total_file_size must be lower than %ld bytes", MAX_FILE_SIZE);
            return -1;
        }

        ctx->timer_created = FLB_FALSE;
        ctx->timer_ms = (int) (ctx->upload_timeout / 6) * 1000;
        flb_plg_debug(ctx->ins, "Using upload size %lu bytes", ctx->file_size);
    }

    flb_output_set_context(ins, ctx);

    /* Network mode IPv6 */
    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Create mutex for acquiring oauth tokens  and getting ingestion resources (they
     * are shared across flush coroutines)
     */
    pthread_mutex_init(&ctx->token_mutex, NULL);
    pthread_mutex_init(&ctx->resources_mutex, NULL);
    pthread_mutex_init(&ctx->blob_mutex, NULL);

    /*
     * Create upstream context for Kusto Ingestion endpoint
     */
    ctx->u = flb_upstream_create_url(config, ctx->ingestion_endpoint, io_flags, ins->tls);
    if (ctx->buffering_enabled ==  FLB_TRUE){
        flb_stream_disable_flags(&ctx->u->base, FLB_IO_ASYNC);
        ctx->u->base.net.io_timeout = ctx->io_timeout;
        ctx->has_old_buffers = azure_kusto_store_has_data(ctx);
    }
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "upstream creation failed");
        return -1;
    }

    /*
     * Create upstream context for Kusto Cluster endpoint (for streaming ingestion)
     * Convert ingestion endpoint to cluster endpoint by removing "ingest-" prefix
     */
    if (ctx->streaming_ingestion_enabled == FLB_TRUE) {
        flb_sds_t cluster_endpoint = NULL;
        const char *prefix = "ingest-";
        const char *schema_end = strstr(ctx->ingestion_endpoint, "://");
        const char *hostname_start = schema_end ? schema_end + 3 : ctx->ingestion_endpoint;
        
        /* Check if hostname starts with "ingest-" prefix */
        if (strncmp(hostname_start, prefix, strlen(prefix)) == 0) {
            /* Create cluster endpoint by removing "ingest-" prefix from hostname */
            cluster_endpoint = flb_sds_create(ctx->ingestion_endpoint);
            if (!cluster_endpoint) {
                flb_plg_error(ctx->ins, "failed to create cluster endpoint string");
                flb_upstream_destroy(ctx->u);
                ctx->u = NULL;
                return -1;
            }

            /* Find the position in our copy and remove the prefix */
            char *copy_hostname = strstr(cluster_endpoint, "://");
            if (copy_hostname) {
                copy_hostname += 3;
                /* Verify the prefix is still at the expected position */
                if (strncmp(copy_hostname, prefix, strlen(prefix)) == 0) {
                    memmove(copy_hostname, copy_hostname + strlen(prefix), 
                            strlen(copy_hostname + strlen(prefix)) + 1);
                    flb_sds_len_set(cluster_endpoint, flb_sds_len(cluster_endpoint) - strlen(prefix));
                }
            }

            /* Create upstream connection to cluster endpoint */
            ctx->u_cluster = flb_upstream_create_url(config, cluster_endpoint, io_flags, ins->tls);
            if (!ctx->u_cluster) {
                flb_plg_error(ctx->ins, "cluster upstream creation failed for endpoint: %s", cluster_endpoint);
                flb_sds_destroy(cluster_endpoint);
                flb_upstream_destroy(ctx->u);
                ctx->u = NULL;
                return -1;
            }

            flb_sds_destroy(cluster_endpoint);
        } else {
            flb_plg_warn(ctx->ins, "ingestion endpoint hostname does not start with 'ingest-' prefix, using as cluster endpoint");
            /* Use ingestion endpoint directly as cluster endpoint */
            ctx->u_cluster = flb_upstream_create_url(config, ctx->ingestion_endpoint, io_flags, ins->tls);
            if (!ctx->u_cluster) {
                flb_plg_error(ctx->ins, "cluster upstream creation failed");
                flb_upstream_destroy(ctx->u);
                ctx->u = NULL;
                return -1;
            }
        }
    }

    flb_plg_debug(ctx->ins, "async flag is %d", flb_stream_is_async(&ctx->u->base));

    /* Create oauth2 context */
    ctx->o =
        flb_oauth2_create(ctx->config, ctx->oauth_url, FLB_AZURE_KUSTO_TOKEN_REFRESH);
    if (!ctx->o) {
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        return -1;
    }
    flb_output_upstream_set(ctx->u, ins);

    flb_plg_debug(ctx->ins, "azure kusto init completed");

    return 0;
}


/**
     * This function formats log data for Azure Kusto ingestion.
     * It processes a batch of log records, encodes them in a specific format,
     * and outputs the formatted data.
     *
     * Parameters:
     * - ctx: Context containing configuration and state for Azure Kusto.
     * - tag: A string tag associated with the log data.
     * - tag_len: Length of the tag string.
     * - data: Pointer to the raw log data in msgpack format.
     * - bytes: Size of the raw log data.
     * - out_data: Pointer to store the formatted output data.
     * - out_size: Pointer to store the size of the formatted output data.
     *
     * Returns:
     * - 0 on success, or -1 on error.
     */
static int azure_kusto_format(struct flb_azure_kusto *ctx, const char *tag, int tag_len,
                              const void *data, size_t bytes, void **out_data,
                              size_t *out_size,
                              struct flb_config *config)
{
    int index;
    int records = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct tm tms;
    char time_formatted[32];
    size_t s;
    int len;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;
    flb_sds_t out_buf;

    /* Create array for all records */
    records = flb_mp_count(data, bytes);
    if (records <= 0) {
        flb_plg_error(ctx->ins, "error counting msgpack entries");
        return -1;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event decoder initialization error : %d", ret);
        return -1;
    }

    /* Initialize the output buffer */
    out_buf = flb_sds_create_size(1024);
    if (!out_buf) {
        flb_plg_error(ctx->ins, "error creating output buffer");
        flb_log_event_decoder_destroy(&log_decoder);
        return -1;
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    while ((ret = flb_log_event_decoder_next(&log_decoder, &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        msgpack_sbuffer_clear(&mp_sbuf);

        int map_size = 1;
        if (ctx->include_time_key == FLB_TRUE) {
            map_size++;
        }
        if (ctx->include_tag_key == FLB_TRUE) {
            map_size++;
        }

        msgpack_pack_map(&mp_pck, map_size);

        /* include_time_key */
        if (ctx->include_time_key == FLB_TRUE) {
            msgpack_pack_str(&mp_pck, flb_sds_len(ctx->time_key));
            msgpack_pack_str_body(&mp_pck, ctx->time_key, flb_sds_len(ctx->time_key));

            gmtime_r(&log_event.timestamp.tm.tv_sec, &tms);
            s = strftime(time_formatted, sizeof(time_formatted) - 1, FLB_PACK_JSON_DATE_ISO8601_FMT, &tms);
            len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s, ".%03" PRIu64 "Z",
                    (uint64_t) log_event.timestamp.tm.tv_nsec / 1000000);
            s += len;
            msgpack_pack_str(&mp_pck, s);
            msgpack_pack_str_body(&mp_pck, time_formatted, s);
        }

        /* include_tag_key */
        if (ctx->include_tag_key == FLB_TRUE) {
            msgpack_pack_str(&mp_pck, flb_sds_len(ctx->tag_key));
            msgpack_pack_str_body(&mp_pck, ctx->tag_key, flb_sds_len(ctx->tag_key));
            msgpack_pack_str(&mp_pck, tag_len);
            msgpack_pack_str_body(&mp_pck, tag, tag_len);
        }

        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->log_key));
        msgpack_pack_str_body(&mp_pck, ctx->log_key, flb_sds_len(ctx->log_key));

        if (log_event.group_attributes != NULL && log_event.body != NULL) {
            msgpack_pack_map(&mp_pck,
                                 log_event.group_attributes->via.map.size +
                                 log_event.metadata->via.map.size +
                                 log_event.body->via.map.size);

            for (index = 0; index < log_event.group_attributes->via.map.size; index++) { 
                msgpack_pack_object(&mp_pck, log_event.group_attributes->via.map.ptr[index].key);
                msgpack_pack_object(&mp_pck, log_event.group_attributes->via.map.ptr[index].val);
            }

            for (index = 0; index < log_event.metadata->via.map.size; index++) {
                msgpack_pack_object(&mp_pck, log_event.metadata->via.map.ptr[index].key);
                msgpack_pack_object(&mp_pck, log_event.metadata->via.map.ptr[index].val);
            }

            for (index = 0; index < log_event.body->via.map.size; index++) {
                msgpack_pack_object(&mp_pck, log_event.body->via.map.ptr[index].key);
                msgpack_pack_object(&mp_pck, log_event.body->via.map.ptr[index].val);
            }
        }
        else if (log_event.body != NULL) {
            msgpack_pack_object(&mp_pck, *log_event.body);
        }
        else {
            msgpack_pack_str(&mp_pck, 20);
            msgpack_pack_str_body(&mp_pck, "log_attribute_missing", 20);
        }

        flb_sds_t json_record = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                                            config->json_escape_unicode);
        if (!json_record) {
            flb_plg_error(ctx->ins, "error converting msgpack to JSON");
            flb_sds_destroy(out_buf);
            msgpack_sbuffer_destroy(&mp_sbuf);
            flb_log_event_decoder_destroy(&log_decoder);
            return -1;
        }

        /* Concatenate the JSON record to the output buffer */
        out_buf = flb_sds_cat(out_buf, json_record, flb_sds_len(json_record));
        out_buf = flb_sds_cat(out_buf, "\n", 1);

        flb_sds_destroy(json_record);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_log_event_decoder_destroy(&log_decoder);

    *out_data = out_buf;
    *out_size = flb_sds_len(out_buf);

    return 0;
}

static int buffer_chunk(void *out_context, struct azure_kusto_file *upload_file,
                        flb_sds_t chunk, int chunk_size,
                        flb_sds_t tag, size_t tag_len)
{
    int ret;
    struct flb_azure_kusto *ctx = out_context;

    flb_plg_trace(ctx->ins, "Buffering chunk %d", chunk_size);

    ret = azure_kusto_store_buffer_put(ctx, upload_file, tag,
                                       tag_len, chunk, chunk_size);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not buffer chunk. ");
        return -1;
    }
    return 0;
}

/**
 * @brief Initialize the flush process for Azure Kusto output plugin.
 *
 * This function is responsible for setting up the initial conditions required
 * for flushing data to Azure Kusto. It performs the following tasks:
 *
 * 1. **Old Buffer Cleanup**: Checks if there are any old buffers from previous
 *    executions that need to be sent to Azure Kusto. If such buffers exist, it
 *    attempts to ingest all chunks of data. If the ingestion fails, it logs an
 *    error and marks the buffers to be retried later.
 *
 * 2. **Upload Timer Setup**: If not already created, it sets up a periodic timer
 *    that checks for uploads ready for completion. This timer is crucial for
 *    ensuring that data is uploaded at regular intervals.
 *
 * @param out_context Pointer to the output context, specifically the Azure Kusto context.
 * @param config Pointer to the Fluent Bit configuration structure.
 */
static void flush_init(void *out_context, struct flb_config *config)
{
    int ret;
    struct flb_azure_kusto *ctx = out_context;
    struct flb_sched *sched;

    flb_plg_debug(ctx->ins,
                  "inside flush_init with old_buffers as %d",
                  ctx->has_old_buffers);

    /* clean up any old buffers found on startup */
    if (ctx->has_old_buffers == FLB_TRUE) {
        flb_plg_info(ctx->ins,
                     "Sending locally buffered data from previous "
                     "executions to kusto; buffer=%s",
                     ctx->fs->root_path);
        ctx->has_old_buffers = FLB_FALSE;
        ret = ingest_all_chunks(ctx, config);
        if (ret < 0) {
            ctx->has_old_buffers = FLB_TRUE;
            flb_plg_error(ctx->ins,
                          "Failed to send locally buffered data left over "
                          "from previous executions; will retry. Buffer=%s",
                          ctx->fs->root_path);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }
    else {
        flb_plg_debug(ctx->ins,
                     "Did not find any local buffered data from previous "
                     "executions to kusto; buffer=%s",
                     ctx->fs->root_path);
    }

    /*
    * create a timer that will run periodically and check if uploads
    * are ready for completion
    * this is created once on the first flush
    */
    if (ctx->timer_created == FLB_FALSE) {
        flb_plg_debug(ctx->ins,
                      "Creating upload timer with frequency %ds",
                      ctx->timer_ms / 1000);

        sched = flb_sched_ctx_get();

        ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                        ctx->timer_ms, cb_azure_kusto_ingest, ctx, NULL);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to create upload timer");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        ctx->timer_created = FLB_TRUE;
    }
}

/**
 * This function handles the flushing of event data to Azure Kusto.
 * It manages both buffered and non-buffered modes, handles JSON formatting,
 * compression, and manages file uploads based on conditions like timeout and file size.
 *
 * @param event_chunk The event chunk containing the data to be flushed.
 * @param out_flush The output flush context.
 * @param i_ins The input instance (unused).
 * @param out_context The output context, specifically for Azure Kusto.
 * @param config The configuration context (unused).
 */
static void cb_azure_kusto_flush(struct flb_event_chunk *event_chunk,
                                 struct flb_output_flush *out_flush,
                                 struct flb_input_instance *i_ins, void *out_context,
                                 struct flb_config *config)
{
    int ret;
    flb_sds_t json = NULL;
    size_t json_size;
    size_t tag_len;
    struct flb_azure_kusto *ctx = out_context;
    int is_compressed = FLB_FALSE;
    struct azure_kusto_file *upload_file = NULL;
    int upload_timeout_check = FLB_FALSE;
    int total_file_size_check = FLB_FALSE;
    flb_sds_t tag_name = NULL;
    size_t tag_name_len;

    (void)i_ins;
    (void)config;

    void *final_payload = NULL;
    size_t final_payload_size = 0;

    flb_plg_debug(ctx->ins, "flushing bytes for event tag %s and size %zu", event_chunk->tag ,event_chunk->size);

    /* Get the length of the event tag */
    tag_len = flb_sds_len(event_chunk->tag);

    if (ctx->buffering_enabled == FLB_TRUE) {
    /* Determine the tag name based on the unify_tag setting */
        if (ctx->unify_tag == FLB_TRUE){
            tag_name = flb_sds_create("fluentbit-buffer-file-unify-tag.log");
        }
        else {
            tag_name = event_chunk->tag;
        }
        tag_name_len = flb_sds_len(tag_name);
        /* Initialize the flush process */
        flush_init(ctx,config);

        /* Reformat msgpack to JSON payload */
        ret = azure_kusto_format(ctx, tag_name, tag_name_len, event_chunk->data,
                                 event_chunk->size, (void **)&json, &json_size,
                                 config);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot reformat data into json");
            ret = FLB_RETRY;
            goto error;
        }

        /* Get a file candidate matching the given 'tag' */
        upload_file = azure_kusto_store_file_get(ctx,
                                                 tag_name,
                                                 tag_name_len);

        /* Check if the file has failed to upload too many times */
        if (upload_file != NULL && upload_file->failures >= ctx->scheduler_max_retries) {
            flb_plg_warn(ctx->ins, "File with tag %s failed to send %d times, will not "
                                   "retry", event_chunk->tag, ctx->scheduler_max_retries);
            if (ctx->delete_on_max_upload_error){
                azure_kusto_store_file_delete(ctx, upload_file);
            }
            else {
                azure_kusto_store_file_inactive(ctx, upload_file);
            }
            upload_file = NULL;
        }

        /* Check if the upload timeout has elapsed */
        if (upload_file != NULL && time(NULL) >
                                   (upload_file->create_time + ctx->upload_timeout)) {
            upload_timeout_check = FLB_TRUE;
            flb_plg_trace(ctx->ins, "upload_timeout reached for %s",
                          event_chunk->tag);
        }

        /* Check if the total file size has been exceeded */
        if (upload_file && upload_file->size + json_size > ctx->file_size) {
            flb_plg_trace(ctx->ins, "total_file_size exceeded %s",
                          event_chunk->tag);
            total_file_size_check = FLB_TRUE;
        }

        /* If the file is ready for upload */
        if ((upload_file != NULL) && (upload_timeout_check == FLB_TRUE || total_file_size_check == FLB_TRUE)) {
            flb_plg_debug(ctx->ins, "uploading file %s with size %zu", upload_file->fsf->name, upload_file->size);
            /* Load or refresh ingestion resources */
            ret = azure_kusto_load_ingestion_resources(ctx, config);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "cannot load ingestion resources");
                ret = FLB_RETRY;
                goto error;
            }

            /* Ingest data to kusto */
            ret = ingest_to_kusto(ctx, json, upload_file,
                                      tag_name,
                                      tag_name_len);

            if (ret == 0){
                if (ctx->buffering_enabled == FLB_TRUE && ctx->buffer_file_delete_early == FLB_TRUE){
                    flb_plg_debug(ctx->ins, "buffer file already deleted after blob creation");
                    ret = FLB_OK;
                    goto cleanup;
                }
                else{
                    ret = azure_kusto_store_file_delete(ctx, upload_file);
                    if (ret != 0){
                        /* File couldn't be deleted */
                        ret = FLB_RETRY;
                        if (upload_file){
                            azure_kusto_store_file_unlock(upload_file);
                            upload_file->failures += 1;
                        }
                        goto error;
                    }
                    else{
                        /* File deleted successfully */
                        ret = FLB_OK;
                        goto cleanup;
                    }
                }
            }
            else{
                flb_plg_error(ctx->ins, "azure_kusto:: unable to ingest data into kusto : retrying");
                ret = FLB_RETRY;
                if (upload_file){
                    azure_kusto_store_file_unlock(upload_file);
                    upload_file->failures += 1;
                }
                goto cleanup;
            }
        }

        /* Buffer the current chunk in the filesystem */
        ret = buffer_chunk(ctx, upload_file, json, json_size,
                           tag_name, tag_name_len);

        if (ret == 0) {
            flb_plg_debug(ctx->ins, "buffered chunk %s", event_chunk->tag);
            ret = FLB_OK;
        }
        else {
            flb_plg_error(ctx->ins, "failed to buffer chunk %s", event_chunk->tag);
            ret = FLB_RETRY;
        }
        goto cleanup;

    }
    else {
        /* Buffering mode is disabled, proceed with regular flush */

        /* Reformat msgpack data to JSON payload */
        ret = azure_kusto_format(ctx, event_chunk->tag, tag_len, event_chunk->data,
                                 event_chunk->size, (void **)&json, &json_size,
                                 config);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot reformat data into json");
            ret = FLB_RETRY;
            goto error;
        }

        flb_plg_debug(ctx->ins, "payload size before compression %zu", json_size);
        /* Map buffer */
        final_payload = json;
        final_payload_size = json_size;
        /* Check if compression is enabled */
        if (ctx->compression_enabled == FLB_TRUE) {
            ret = flb_gzip_compress((void *) json, json_size,
                                    &final_payload, &final_payload_size);
            if (ret != 0) {
                flb_plg_error(ctx->ins,
                              "cannot gzip payload");
                ret = FLB_ERROR;
                goto error;
            }
            else {
                is_compressed = FLB_TRUE;
                flb_plg_debug(ctx->ins, "enabled payload gzip compression");
                /* JSON buffer will be cleared at cleanup: */
            }
        }
        flb_plg_trace(ctx->ins, "payload size after compression %zu", final_payload_size);

        /* 
         * Load ingestion resources regardless of streaming mode.
         * This is required because streaming ingestion may fall back to queued ingestion
         * when payload size exceeds limits, and queued ingestion requires these resources.
         */
        ret = azure_kusto_load_ingestion_resources(ctx, config);
        flb_plg_trace(ctx->ins, "load_ingestion_resources: ret=%d", ret);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot load ingestion resources");
            ret = FLB_RETRY;
            goto error;
        }

        /* Check if streaming ingestion is enabled */
        if (ctx->streaming_ingestion_enabled == FLB_TRUE) {
            /* 
             * Perform streaming ingestion to Kusto.
             * Note: kusto streaming ingestion may automatically fall back to queued ingestion
             * if the payload size exceeds limits ie uncompressed payload size > 4MB.
             */
            flb_plg_debug(ctx->ins, "[FLUSH_STREAMING] Initiating streaming ingestion to Kusto");
            ret = azure_kusto_streaming_ingestion(ctx, event_chunk->tag, tag_len, final_payload, final_payload_size, json_size);

            if (ret != 0) {
                flb_plg_error(ctx->ins, "[FLUSH_STREAMING] ERROR: Streaming ingestion failed, will retry");
                ret = FLB_RETRY;
                goto error;
            } else {
                flb_plg_info(ctx->ins, "[FLUSH_STREAMING] SUCCESS: Streaming ingestion completed successfully");
            }
        } else {
            flb_plg_debug(ctx->ins, "[FLUSH_QUEUED] Using queued ingestion mode (streaming ingestion disabled)");

            /* Perform queued ingestion to Kusto */
            ret = azure_kusto_queued_ingestion(ctx, event_chunk->tag, tag_len, final_payload, final_payload_size, NULL);
            flb_plg_trace(ctx->ins, "after kusto queued ingestion %d", ret);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "cannot perform queued ingestion");
                ret = FLB_RETRY;
                goto error;
            }
        }

        ret = FLB_OK;
        goto cleanup;
    }

    cleanup:
    /* Cleanup resources */
    if (json) {
        flb_sds_destroy(json);
    }
    if (is_compressed && final_payload) {
        flb_free(final_payload);
    }
    if (tag_name) {
        flb_sds_destroy(tag_name);
    }
    FLB_OUTPUT_RETURN(ret);

    error:
    /* Error handling and cleanup */
    if (json) {
        flb_sds_destroy(json);
    } 
    if (is_compressed && final_payload) {
        flb_free(final_payload);
    }
    if (tag_name) {
        flb_sds_destroy(tag_name);
    }
    FLB_OUTPUT_RETURN(ret);
}

/**
 * cb_azure_kusto_exit - Clean up and finalize the Azure Kusto plugin context.
 *
 * This function is responsible for performing cleanup operations when the
 * Azure Kusto plugin is exiting. It ensures that all resources are properly
 * released and any remaining data is sent to Azure Kusto before the plugin
 * shuts down.
 *
 * Functionality:
 * - Checks if the plugin context (`ctx`) is valid. If not, it returns an error.
 * - If there is locally buffered data, it attempts to send all chunks to Azure
 *   Kusto using the `ingest_all_chunks` function. Logs an error if the operation
 *   fails.
 * - Destroys any active upstream connections (`ctx->u` and `ctx->imds_upstream`)
 *   to free network resources.
 * - Destroys mutexes (`resources_mutex`, `token_mutex`, `blob_mutex`) to ensure
 *   proper synchronization cleanup.
 * - Calls `azure_kusto_store_exit` to perform any additional storage-related
 *   cleanup operations.
 * - Finally, it calls `flb_azure_kusto_conf_destroy` to free the plugin context
 *   and its associated resources.
 *
 * Parameters:
 * - data: A pointer to the plugin context (`struct flb_azure_kusto`).
 * - config: A pointer to the Fluent Bit configuration (`struct flb_config`).
 *
 * Returns:
 * - 0 on successful cleanup.
 * - -1 if the context is invalid or if an error occurs during cleanup.
 */
static int cb_azure_kusto_exit(void *data, struct flb_config *config)
{
    struct flb_azure_kusto *ctx = data;
    int ret = -1;

    if (!ctx) {
        return -1;
    }


    if (ctx->buffering_enabled == FLB_TRUE){
        if (azure_kusto_store_has_data(ctx) == FLB_TRUE) {
            flb_plg_info(ctx->ins, "Sending all locally buffered data to Kusto");
            ret = ingest_all_chunks(ctx, config);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "Could not send all chunks on exit");
            }
        }
        azure_kusto_store_exit(ctx);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
        ctx->u = NULL;
    }

    if (ctx->u_cluster) {
        flb_upstream_destroy(ctx->u_cluster);
        ctx->u_cluster = NULL;
    }

    pthread_mutex_destroy(&ctx->resources_mutex);
    pthread_mutex_destroy(&ctx->token_mutex);
    pthread_mutex_destroy(&ctx->blob_mutex);

    flb_azure_kusto_conf_destroy(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {FLB_CONFIG_MAP_STR, "tenant_id", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, tenant_id),
     "Set the tenant ID of the AAD application used for authentication"},
    {FLB_CONFIG_MAP_STR, "client_id", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, client_id),
     "Set the client ID (Application ID) of the AAD application or the user-assigned managed identity's client ID when using managed identity authentication"},
    {FLB_CONFIG_MAP_STR, "client_secret", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, client_secret),
     "Set the client secret (Application Password) of the AAD application used for "
     "authentication"},
    {FLB_CONFIG_MAP_STR, "workload_identity_token_file", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, workload_identity_token_file),
     "Set the token file path for workload identity authentication"},
    {FLB_CONFIG_MAP_STR, "auth_type", "service_principal", 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, auth_type_str),
     "Set the authentication type: 'service_principal', 'managed_identity', or 'workload_identity'. "
     "For managed_identity, use 'system' as client_id for system-assigned identity, or specify the managed identity's client ID"},
    {FLB_CONFIG_MAP_STR, "ingestion_endpoint", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, ingestion_endpoint),
     "Set the Kusto cluster's ingestion endpoint URL (e.g. "
     "https://ingest-mycluster.eastus.kusto.windows.net)"},
    {FLB_CONFIG_MAP_STR, "database_name", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, database_name), "Set the database name"},
    {FLB_CONFIG_MAP_STR, "table_name", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, table_name), "Set the table name"},
    {FLB_CONFIG_MAP_STR, "ingestion_mapping_reference", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, ingestion_mapping_reference),
     "Set the ingestion mapping reference"},
    {FLB_CONFIG_MAP_STR, "log_key", FLB_AZURE_KUSTO_DEFAULT_LOG_KEY, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, log_key), "The key name of event payload"},
    {FLB_CONFIG_MAP_BOOL, "include_tag_key", "true", 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, include_tag_key),
     "If enabled, tag is appended to output. "
     "The key name is used 'tag_key' property."},
    {FLB_CONFIG_MAP_STR, "tag_key", FLB_AZURE_KUSTO_DEFAULT_TAG_KEY, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, tag_key),
     "The key name of tag. If 'include_tag_key' is false, "
     "This property is ignored"},
    {FLB_CONFIG_MAP_BOOL, "include_time_key", "true", 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, include_time_key),
     "If enabled, time is appended to output. "
     "The key name is used 'time_key' property."},
    {FLB_CONFIG_MAP_STR, "time_key", FLB_AZURE_KUSTO_DEFAULT_TIME_KEY, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, time_key),
     "The key name of the time. If 'include_time_key' is false, "
     "This property is ignored"},
    {FLB_CONFIG_MAP_TIME, "ingestion_endpoint_connect_timeout", FLB_AZURE_KUSTO_INGEST_ENDPOINT_CONNECTION_TIMEOUT, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, ingestion_endpoint_connect_timeout),
    "Set the connection timeout of various kusto endpoints (kusto ingest endpoint, kusto ingestion blob endpoint, kusto ingestion queue endpoint) in seconds."
    "The default is 60 seconds."},
    {FLB_CONFIG_MAP_BOOL, "compression_enabled", "true", 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, compression_enabled),
    "Enable HTTP payload compression (gzip)."
    "The default is true."},
    {FLB_CONFIG_MAP_BOOL, "streaming_ingestion_enabled", "false", 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, streaming_ingestion_enabled),
    "Enable streaming ingestion. When enabled, data is sent directly to Kusto engine without using blob storage and queues. "
    "Note: Streaming ingestion has a 4MB limit per request and doesn't support buffering."
    "The default is false (uses queued ingestion)."},
    {FLB_CONFIG_MAP_TIME, "ingestion_resources_refresh_interval", FLB_AZURE_KUSTO_RESOURCES_LOAD_INTERVAL_SEC,0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, ingestion_resources_refresh_interval),
    "Set the azure kusto ingestion resources refresh interval"
    "The default is 3600 seconds."},
    {FLB_CONFIG_MAP_BOOL, "buffering_enabled", "false", 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, buffering_enabled), "Enable buffering into disk before ingesting into Azure Kusto."
    },
    {FLB_CONFIG_MAP_STR, "buffer_dir", "/tmp/fluent-bit/azure-kusto/", 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, buffer_dir), "Specifies the location of directory where the buffered data will be stored."
    },
    {FLB_CONFIG_MAP_TIME, "upload_timeout", "30m",
     0, FLB_TRUE, offsetof(struct flb_azure_kusto, upload_timeout),
    "Optionally specify a timeout for uploads. "
    "Fluent Bit will start ingesting buffer files which have been created more than x minutes and haven't reached upload_file_size limit yet.  "
    " Default is 30m."
    },
    {FLB_CONFIG_MAP_SIZE, "upload_file_size", "200M",
     0, FLB_TRUE, offsetof(struct flb_azure_kusto, file_size),
    "Specifies the size of files to be uploaded in MBs. Default is 200MB"
    },
    {FLB_CONFIG_MAP_STR, "azure_kusto_buffer_key", "key",0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, azure_kusto_buffer_key),
    "Set the azure kusto buffer key which needs to be specified when using multiple instances of azure kusto output plugin and buffering is enabled"
    },
    {FLB_CONFIG_MAP_SIZE, "store_dir_limit_size", FLB_AZURE_KUSTO_BUFFER_DIR_MAX_SIZE,0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, store_dir_limit_size),
    "Set the max size of the buffer directory. Default is 8GB"
    },
    {FLB_CONFIG_MAP_BOOL, "buffer_file_delete_early", "false",0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, buffer_file_delete_early),
    "Whether to delete the buffered file early after successful blob creation. Default is false"
    },
    {FLB_CONFIG_MAP_BOOL, "unify_tag", "true",0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, unify_tag),
    "This creates a single buffer file when the buffering mode is ON. Default is true"
    },
    {FLB_CONFIG_MAP_INT, "blob_uri_length", "64",0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, blob_uri_length),
    "Set the length of generated blob uri before ingesting to kusto. Default is 64"
    },
    {FLB_CONFIG_MAP_INT, "scheduler_max_retries", "3",0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, scheduler_max_retries),
    "Set the maximum number of retries for ingestion using the scheduler. Default is 3"
    },
    {FLB_CONFIG_MAP_BOOL, "delete_on_max_upload_error", "false",0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, delete_on_max_upload_error),
    "Whether to delete the buffer file on maximum upload errors. Default is false"
    },
    {FLB_CONFIG_MAP_TIME, "io_timeout", "60s",0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, io_timeout),
    "HTTP IO timeout. Default is 60s"
    },
    /* EOF */
    {0}};

struct flb_output_plugin out_azure_kusto_plugin = {
    .name = "azure_kusto",
    .description = "Send events to Kusto (Azure Data Explorer)",
    .cb_init = cb_azure_kusto_init,
    .cb_flush = cb_azure_kusto_flush,
    .cb_exit = cb_azure_kusto_exit,
    .config_map = config_map,
    /* Plugin flags */
    .flags = FLB_OUTPUT_NET | FLB_IO_TLS,
};
