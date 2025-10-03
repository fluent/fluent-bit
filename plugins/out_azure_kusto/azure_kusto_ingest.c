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

#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_version.h>

#include <math.h>
#include <msgpack.h>

#include "azure_kusto_ingest.h"
#include "azure_kusto_store.h"

/* not really uuid but a random string in the form 00000000-0000-0000-0000-000000000000 */
static char *generate_uuid()
{
    char *chars = "0123456789abcdef";
    char *uuid;
    int i;
    uint64_t rand;

    uuid = flb_malloc(37);
    if (!uuid) {
        flb_errno();
        return NULL;
    }

    for (i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            uuid[i] = '-';
            continue;
        }

        if (flb_random_bytes((unsigned char *)&rand, sizeof(uint64_t))) {
            rand = time(NULL);
        }
        uuid[i] = chars[rand % 16];
    }
    uuid[36] = '\0';

    return uuid;
}

static char *base64_encode(flb_sds_t s, size_t len, size_t *out_len)
{
    char *b64;
    int ret;
    size_t buffer_len = 4 * ceil(((double)len / 3) + 1);

    b64 = flb_malloc(buffer_len);
    if (!b64) {
        flb_errno();
        return NULL;
    }

    ret = flb_base64_encode((unsigned char *)b64, buffer_len, out_len, (unsigned char *)s,
                            len);
    if (ret != 0) {
        flb_error("cannot encode string %s into base64", s);
        flb_free(b64);
        return NULL;
    }

    return b64;
}

static flb_sds_t azure_kusto_create_blob_uri(struct flb_azure_kusto *ctx,
                                             struct flb_upstream_node *u_node,
                                             flb_sds_t blob_id)
{
    int ret;
    flb_sds_t uri = NULL;
    char *blob_uri;
    size_t blob_uri_size;
    char *blob_sas;
    size_t blob_sas_size;
    const char *extension;

    if (ctx->compression_enabled) {
        extension = ".multijson.gz";
    }
    else {
        extension = ".multijson";
    }

    ret = flb_hash_table_get(u_node->ht, AZURE_KUSTO_RESOURCE_UPSTREAM_URI, 3,
                             (void **)&blob_uri, &blob_uri_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error getting blob uri");
        return NULL;
    }

    ret = flb_hash_table_get(u_node->ht, AZURE_KUSTO_RESOURCE_UPSTREAM_SAS, 3,
                             (void **)&blob_sas, &blob_sas_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error getting blob sas token");
        return NULL;
    }

    /* uri will be https://<blob_host>/<container_uri>/<blob_id>.multijson?<sas_token> */
    uri = flb_sds_create_size(flb_sds_len(u_node->host) + blob_uri_size + blob_sas_size +
                              flb_sds_len(blob_id) + 11 + strlen(extension));

    if (uri) {
        flb_sds_snprintf(&uri, flb_sds_alloc(uri), "https://%s%s/%s%s?%s",
                         u_node->host, blob_uri, blob_id, extension ,blob_sas);
        flb_plg_debug(ctx->ins, "created blob uri %s", uri);
    }
    else {
        flb_plg_error(ctx->ins, "cannot create blob uri buffer");
    }

    return uri;
}

static flb_sds_t azure_kusto_create_blob(struct flb_azure_kusto *ctx, flb_sds_t blob_id,
                                         flb_sds_t payload, size_t payload_size)
{
    int ret = -1;
    flb_sds_t uri = NULL;
    struct flb_upstream_node *u_node;
    struct flb_forward_config *fc = NULL;
    struct flb_connection *u_conn = NULL;
    struct flb_http_client *c = NULL;
    size_t resp_size;
    time_t now;
    struct tm tm;
    char tmp[64];
    int len;

    struct timespec ts;

    now = time(NULL);
    gmtime_r(&now, &tm);
    len = strftime(tmp, sizeof(tmp) - 1, "%a, %d %b %Y %H:%M:%S GMT", &tm);

    u_node = flb_upstream_ha_node_get(ctx->resources->blob_ha);
    if (!u_node) {
        flb_plg_error(ctx->ins, "error getting blob upstream");
        return NULL;
    }

    /* Get forward_config stored in node opaque data */
    fc = flb_upstream_node_get_data(u_node);

    flb_plg_debug(ctx->ins,"inside blob after upstream ha node get");
    u_node->u->base.net.connect_timeout = ctx->ingestion_endpoint_connect_timeout;
    if (ctx->buffering_enabled ==  FLB_TRUE){
        u_node->u->base.flags &= ~(FLB_IO_ASYNC);
        u_node->u->base.net.io_timeout = ctx->io_timeout;
    }
    flb_plg_debug(ctx->ins, "azure_kusto_create_blob -- async flag is %d", flb_stream_is_async(&ctx->u->base));

    flb_plg_debug(ctx->ins,"inside blob after upstream ha node get  :: setting ingestion timeout");
    if (!u_node->u) {
        flb_plg_error(ctx->ins, "upstream data is null");
        return NULL;
    }
    u_conn = flb_upstream_conn_get(u_node->u);

    flb_plg_debug(ctx->ins,"inside blob after upstream ha node get :: after getting connection");
    if (u_conn) {
        if (pthread_mutex_lock(&ctx->blob_mutex)) {
            flb_plg_error(ctx->ins, "error unlocking mutex");
            goto cleanup;
        }

        flb_plg_debug(ctx->ins,"inside blob before create blob uri");
        uri = azure_kusto_create_blob_uri(ctx, u_node, blob_id);

        if (pthread_mutex_unlock(&ctx->blob_mutex)) {
            flb_plg_error(ctx->ins, "error unlocking mutex");
            goto cleanup;
        }

        if (uri) {
            flb_plg_debug(ctx->ins, "azure_kusto: before calling azure storage api :: value of set io_timeout is %d", u_conn->net->io_timeout);
            flb_plg_debug(ctx->ins, "uploading payload to blob uri: %s", uri);
            c = flb_http_client(u_conn, FLB_HTTP_PUT, uri, payload, payload_size, NULL, 0,
                                NULL, 0);

            if (c) {
                flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
                flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
                flb_http_add_header(c, "x-ms-blob-type", 14, "BlockBlob", 9);
                flb_http_add_header(c, "x-ms-date", 9, tmp, len);
                flb_http_add_header(c, "x-ms-version", 12, "2019-12-12", 10);
                flb_http_add_header(c, "x-ms-client-version", 19, FLB_VERSION_STR, strlen(FLB_VERSION_STR));
                flb_http_add_header(c, "x-ms-app", 8, "Kusto.Fluent-Bit", 16);
                flb_http_add_header(c, "x-ms-user", 9, "Kusto.Fluent-Bit", 16);


                ret = flb_http_do(c, &resp_size);
                flb_plg_debug(ctx->ins,
                              "kusto blob upload request http_do=%i, HTTP Status: %i",
                              ret, c->resp.status);

                if (ret == 0) {
                    /* Validate return status and HTTP status if set */
                    if (c->resp.status != 201) {
                        ret = -1;

                        if (c->resp.payload_size > 0) {
                            flb_plg_error(ctx->ins, "create blob Request failed and returned: \n%s",
                                          c->resp.payload);
                        }
                        else {
                            flb_plg_error(ctx->ins, "create blob Request failed");
                        }
                    }
                }
                else {
                    flb_plg_error(ctx->ins, "create blob cannot send HTTP request");
                }

                flb_http_client_destroy(c);
            }
            else {
                flb_plg_error(ctx->ins,
                              "cannot create HTTP client context for blob container");
            }

            if (ret != 0) {
                flb_sds_destroy(uri);
                uri = NULL;
            }
        }
        else {
            flb_plg_error(ctx->ins, "error creating blob container uri buffer");
        }

        flb_upstream_conn_release(u_conn);
    }
    else {
        flb_plg_error(ctx->ins, "error getting blob container upstream connection");
    }

    return uri;

    cleanup:
    if (c) {
        flb_http_client_destroy(c);
        c = NULL;
    }
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
        u_conn = NULL;
    }
    if (uri) {
        flb_sds_destroy(uri);
        uri = NULL;
    }
    return NULL;
}

static flb_sds_t create_ingestion_message(struct flb_azure_kusto *ctx, flb_sds_t blob_uri,
                                          size_t payload_size)
{
    flb_sds_t message = NULL;
    int ret = 0;
    char *uuid;
    char *message_b64;
    size_t b64_len;
    size_t message_len;


    if (pthread_mutex_lock(&ctx->blob_mutex)) {
        flb_plg_error(ctx->ins, "error unlocking mutex");
        return NULL;
    }

    uuid = generate_uuid();
    if (uuid) {
        message = flb_sds_create(NULL);

        flb_plg_debug(ctx->ins,"uuid :: %s",uuid);
        flb_plg_debug(ctx->ins,"blob uri :: %s",blob_uri);
        flb_plg_debug(ctx->ins,"payload size :: %lu",payload_size);
        flb_plg_debug(ctx->ins,"database_name :: %s",ctx->database_name);
        flb_plg_debug(ctx->ins,"table name :: %s",ctx->table_name);

        if (message) {
            message_len =
                    flb_sds_snprintf(&message, 0,
                                     "{\"Id\": \"%s\", \"BlobPath\": \"%s\", "
                                     "\"RawDataSize\": %lu, \"DatabaseName\": "
                                     "\"%s\", \"TableName\": \"%s\", "
                                     "\"ClientVersionForTracing\": \"Kusto.Fluent-Bit:%s\", "
                                     "\"ApplicationForTracing\": \"%s\", "
                                     "\"AdditionalProperties\": { \"format\": \"multijson\", "
                                     "\"authorizationContext\": \"%s\", "
                                     "\"jsonMappingReference\": \"%s\" }}%c",
                                     uuid, blob_uri, payload_size, ctx->database_name,
                                     ctx->table_name, FLB_VERSION_STR, "Kusto.Fluent-Bit",
                                     ctx->resources->identity_token,
                                     ctx->ingestion_mapping_reference == NULL ? "" : ctx->ingestion_mapping_reference, 0);

            if (message_len != -1) {
                flb_plg_debug(ctx->ins, "created ingestion message:\n%s", message);
                message_b64 = base64_encode(message, message_len, &b64_len);

                if (message_b64) {
                    ret = flb_sds_snprintf(
                            &message, flb_sds_alloc(message),
                            "<QueueMessage><MessageText>%s</MessageText></QueueMessage>%c",
                            message_b64, 0);

                    if (ret == -1) {
                        flb_plg_error(ctx->ins, "error creating ingestion queue message");
                    }

                    flb_free(message_b64);
                }
                else {
                    flb_plg_error(ctx->ins, "error encoding ingestion message to base64");
                }
            }
            else {
                flb_plg_error(ctx->ins, "error creating ingestion message");
                ret = -1;
            }

            if (ret == -1) {
                flb_sds_destroy(message);
                message = NULL;
            }
        }
        else {
            flb_plg_error(ctx->ins, "error creating ingestion message buffer");
        }

        flb_free(uuid);
    }
    else {
        flb_plg_error(ctx->ins, "error generating unique ingestion UUID");
    }


    if (pthread_mutex_unlock(&ctx->blob_mutex)) {
        flb_plg_error(ctx->ins, "error unlocking mutex");
        return NULL;
    }

    return message;
}

static flb_sds_t azure_kusto_create_queue_uri(struct flb_azure_kusto *ctx,
                                              struct flb_upstream_node *u_node)
{
    int ret;
    flb_sds_t uri = NULL;
    char *queue_uri;
    size_t queue_uri_size;
    char *queue_sas;
    size_t queue_sas_size;

    ret = flb_hash_table_get(u_node->ht, AZURE_KUSTO_RESOURCE_UPSTREAM_URI, 3,
                             (void **)&queue_uri, &queue_uri_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error getting queue uri");
        return NULL;
    }

    ret = flb_hash_table_get(u_node->ht, AZURE_KUSTO_RESOURCE_UPSTREAM_SAS, 3,
                             (void **)&queue_sas, &queue_sas_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error getting queue sas token");
        return NULL;
    }

    /* uri will be <container_uri>/messages?<sas_token> */
    uri = flb_sds_create_size(queue_uri_size + queue_sas_size + 11);

    if (uri) {
        flb_sds_snprintf(&uri, flb_sds_alloc(uri), "%s/messages?%s", queue_uri,
                         queue_sas);
        flb_plg_debug(ctx->ins, "created queue uri %s", uri);
    }
    else {
        flb_plg_error(ctx->ins, "cannot create queue uri buffer");
    }

    return uri;
}

static int azure_kusto_enqueue_ingestion(struct flb_azure_kusto *ctx, flb_sds_t blob_uri,
                                         size_t payload_size)
{
    int ret = -1;
    struct flb_upstream_node *u_node;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    flb_sds_t uri;
    flb_sds_t payload;
    size_t resp_size;
    time_t now;
    struct tm tm;
    char tmp[64];
    int len;

    now = time(NULL);
    gmtime_r(&now, &tm);
    len = strftime(tmp, sizeof(tmp) - 1, "%a, %d %b %Y %H:%M:%S GMT", &tm);

    u_node = flb_upstream_ha_node_get(ctx->resources->queue_ha);
    if (!u_node) {
        flb_plg_error(ctx->ins, "error getting queue upstream");
        return -1;
    }

    u_node->u->base.net.connect_timeout = ctx->ingestion_endpoint_connect_timeout;
    if (ctx->buffering_enabled ==  FLB_TRUE){
        u_node->u->base.flags &= ~(FLB_IO_ASYNC);
        u_node->u->base.net.io_timeout = ctx->io_timeout;
    }

    u_conn = flb_upstream_conn_get(u_node->u);

    if (u_conn) {
        if (pthread_mutex_lock(&ctx->blob_mutex)) {
            flb_plg_error(ctx->ins, "error unlocking mutex");
            return -1;
        }
        uri = azure_kusto_create_queue_uri(ctx, u_node);

        if (pthread_mutex_unlock(&ctx->blob_mutex)) {
            flb_plg_error(ctx->ins, "error unlocking mutex");
            return -1;
        }

        if (uri) {
            payload = create_ingestion_message(ctx, blob_uri, payload_size);

            if (payload) {
                c = flb_http_client(u_conn, FLB_HTTP_POST, uri, payload,
                                    flb_sds_len(payload), NULL, 0, NULL, 0);

                if (c) {
                    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
                    flb_http_add_header(c, "Content-Type", 12, "application/atom+xml",
                                        20);
                    flb_http_add_header(c, "x-ms-date", 9, tmp, len);
                    flb_http_add_header(c, "x-ms-version", 12, "2019-12-12", 10);
                    flb_http_add_header(c, "x-ms-client-version", 19, FLB_VERSION_STR, strlen(FLB_VERSION_STR));
                    flb_http_add_header(c, "x-ms-app", 8, "Kusto.Fluent-Bit", 16);
                    flb_http_add_header(c, "x-ms-user", 9, "Kusto.Fluent-Bit", 16);

                    ret = flb_http_do(c, &resp_size);
                    flb_plg_debug(ctx->ins,
                                  "kusto queue request http_do=%i, HTTP Status: %i", ret,
                                  c->resp.status);

                    if (ret == 0) {
                        /* Validate return status and HTTP status if set */
                        if (c->resp.status != 201) {
                            ret = -1;

                            if (c->resp.payload_size > 0) {
                                flb_plg_error(ctx->ins,
                                              "kusto queue Request failed and returned: %s",
                                              c->resp.payload);
                            }
                            else {
                                flb_plg_error(ctx->ins, "kusto queue Request failed");
                            }
                        }
                    }
                    else {
                        flb_plg_error(ctx->ins, "kusto queue cannot send HTTP request");
                    }

                    flb_http_client_destroy(c);
                }
                else {
                    flb_plg_error(ctx->ins,
                                  "cannot create HTTP client context for queue");
                }

                flb_sds_destroy(payload);
            }
            else {
                flb_plg_error(ctx->ins, "error creating payload buffer");
            }

            flb_sds_destroy(uri);
        }
        else {
            flb_plg_error(ctx->ins, "error creating queue uri buffer");
        }

        flb_upstream_conn_release(u_conn);
    }
    else {
        flb_plg_error(ctx->ins, "error getting queue upstream connection");
    }

    return ret;
}

/* Function to generate a random alphanumeric string */
void generate_random_string(char *str, size_t length)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const size_t charset_size = sizeof(charset) - 1;

    /* Seed the random number generator with multiple sources of entropy */
    unsigned int seed = (unsigned int)(time(NULL) ^ clock() ^ getpid());
    srand(seed);

    size_t i;
    for (i = 0; i < length; ++i) {
        size_t index = (size_t)rand() % charset_size;
        str[i] = charset[index];
    }

    str[length] = '\0';
}

static flb_sds_t azure_kusto_create_blob_id(struct flb_azure_kusto *ctx, flb_sds_t tag,
                                            size_t tag_len)
{
    flb_sds_t blob_id = NULL;
    struct flb_time tm;
    uint64_t ms;
    char *b64tag = NULL;
    size_t b64_len = 0;
    char *uuid = NULL;
    char timestamp[20]; /* Buffer for timestamp */
    char *generated_random_string = NULL;

    /* Allocate memory for the random string */
    generated_random_string = flb_malloc(ctx->blob_uri_length + 1);
    flb_time_get(&tm);
    ms = ((tm.tm.tv_sec * 1000) + (tm.tm.tv_nsec / 1000000));

    if (!ctx->unify_tag) {
        b64tag = base64_encode(tag, tag_len, &b64_len);
        if (b64tag) {
            /* remove trailing '=' */
            while (b64_len && b64tag[b64_len - 1] == '=') {
                b64tag[b64_len - 1] = '\0';
                b64_len--;
            }
        }
        else {
            flb_plg_error(ctx->ins, "error encoding tag '%s' to base64", tag);
            return NULL;
        }
    }
    else {
        generate_random_string(generated_random_string, ctx->blob_uri_length); /* Generate the random string */
        b64tag = generated_random_string;
        b64_len = strlen(generated_random_string);
    }

    /* Get the current timestamp */
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", tm_info);

    /* Generate a UUID */
    uuid = generate_uuid();
    if (!uuid) {
        flb_plg_error(ctx->ins, "error generating UUID");
        if (!ctx->unify_tag && b64tag) {
            flb_free(b64tag);
        }
        return NULL;
    }

    blob_id = flb_sds_create_size(1024); /* Ensure the size is restricted to 1024 characters */
    if (blob_id) {
        flb_sds_snprintf(&blob_id, 1024, "flb__%s__%s__%s__%llu__%s__%s",
                         ctx->database_name, ctx->table_name, b64tag, ms, timestamp, uuid);
    }
    else {
        flb_plg_error(ctx->ins, "cannot create blob id buffer");
    }

    if (!ctx->unify_tag && b64tag) {
        flb_free(b64tag);
    }
    flb_free(uuid);
    flb_free(generated_random_string);

    return blob_id;
}

int azure_kusto_queued_ingestion(struct flb_azure_kusto *ctx, flb_sds_t tag,
                                 size_t tag_len, flb_sds_t payload, size_t payload_size, struct azure_kusto_file *upload_file )
{
    int ret = -1;
    flb_sds_t blob_id;
    flb_sds_t blob_uri;


    if (pthread_mutex_lock(&ctx->blob_mutex)) {
        flb_plg_error(ctx->ins, "error unlocking mutex");
        return -1;
    }

    /* flb__<db>__<table>__<b64tag>__<timestamp> */
    blob_id = azure_kusto_create_blob_id(ctx, tag, tag_len);


    if (pthread_mutex_unlock(&ctx->blob_mutex)) {
        flb_plg_error(ctx->ins, "error unlocking mutex");
        return -1;
    }

    if (blob_id) {
        blob_uri = azure_kusto_create_blob(ctx, blob_id, payload, payload_size);

        if (blob_uri) {
            if (ctx->buffering_enabled == FLB_TRUE && upload_file != NULL && ctx->buffer_file_delete_early == FLB_TRUE) {
                flb_plg_debug(ctx->ins, "buffering enabled, ingest to blob successfully done and now deleting the buffer file %s", blob_id);
                if (azure_kusto_store_file_delete(ctx, upload_file) != 0) {
                    flb_plg_error(ctx->ins, "blob creation successful but error deleting buffer file %s", blob_id);
                }
            }
            ret = azure_kusto_enqueue_ingestion(ctx, blob_uri, payload_size);

            if (ret != 0) {
                flb_plg_error(ctx->ins, "failed to enqueue ingestion blob to queue");
                ret = -1;
            }

            flb_sds_destroy(blob_uri);
        }
        else {
            flb_plg_error(ctx->ins, "failed to create payload blob uri");
        }

        flb_sds_destroy(blob_id);
    }
    else {
        flb_plg_error(ctx->ins, "cannot create blob id");
    }

    return ret;
}