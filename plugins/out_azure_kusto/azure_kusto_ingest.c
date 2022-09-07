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

#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>

#include <math.h>
#include <msgpack.h>

#include "azure_kusto_ingest.h"

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
                              flb_sds_len(blob_id) + 21);

    if (uri) {
        flb_sds_snprintf(&uri, flb_sds_alloc(uri), "https://%s%s/%s.multijson?%s",
                         u_node->host, blob_uri, blob_id, blob_sas);
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
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    size_t resp_size;
    time_t now;
    struct tm tm;
    char tmp[64];
    int len;

    now = time(NULL);
    gmtime_r(&now, &tm);
    len = strftime(tmp, sizeof(tmp) - 1, "%a, %d %b %Y %H:%M:%S GMT", &tm);

    u_node = flb_upstream_ha_node_get(ctx->resources->blob_ha);
    if (!u_node) {
        flb_plg_error(ctx->ins, "error getting blob upstream");
        return NULL;
    }

    u_conn = flb_upstream_conn_get(u_node->u);

    if (u_conn) {
        uri = azure_kusto_create_blob_uri(ctx, u_node, blob_id);

        if (uri) {
            flb_plg_debug(ctx->ins, "uploading payload to blob uri: %s", uri);
            c = flb_http_client(u_conn, FLB_HTTP_PUT, uri, payload, payload_size, NULL, 0,
                                NULL, 0);

            if (c) {
                flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
                flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
                flb_http_add_header(c, "x-ms-blob-type", 14, "BlockBlob", 9);
                flb_http_add_header(c, "x-ms-date", 9, tmp, len);
                flb_http_add_header(c, "x-ms-version", 12, "2019-12-12", 10);

                ret = flb_http_do(c, &resp_size);
                flb_plg_debug(ctx->ins,
                              "kusto blob upload request http_do=%i, HTTP Status: %i",
                              ret, c->resp.status);

                if (ret == 0) {
                    /* Validate return status and HTTP status if set */
                    if (c->resp.status != 201) {
                        ret = -1;

                        if (c->resp.payload_size > 0) {
                            flb_plg_debug(ctx->ins, "Request failed and returned: \n%s",
                                          c->resp.payload);
                        }
                        else {
                            flb_plg_debug(ctx->ins, "Request failed");
                        }
                    }
                }
                else {
                    flb_plg_error(ctx->ins, "cannot send HTTP request");
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

    uuid = generate_uuid();
    if (uuid) {
        message = flb_sds_create(NULL);

        if (message) {
            message_len =
                flb_sds_snprintf(&message, 0,
                                 "{\"Id\": \"%s\", \"BlobPath\": \"%s\", "
                                 "\"RawDataSize\": %lu, \"DatabaseName\": "
                                 "\"%s\", \"TableName\": \"%s\","
                                 "\"AdditionalProperties\": { \"format\": \"multijson\", "
                                 "\"authorizationContext\": "
                                 "\"%s\", \"jsonMappingReference\": \"%s\" }}%c",
                                 uuid, blob_uri, payload_size, ctx->database_name,
                                 ctx->table_name, ctx->resources->identity_token,
                                 ctx->ingestion_mapping_reference == NULL
                                     ? ""
                                     : ctx->ingestion_mapping_reference, 0);

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

    u_conn = flb_upstream_conn_get(u_node->u);

    if (u_conn) {
        uri = azure_kusto_create_queue_uri(ctx, u_node);

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

                    ret = flb_http_do(c, &resp_size);
                    flb_plg_debug(ctx->ins,
                                  "kusto queue request http_do=%i, HTTP Status: %i", ret,
                                  c->resp.status);

                    if (ret == 0) {
                        /* Validate return status and HTTP status if set */
                        if (c->resp.status != 201) {
                            ret = -1;

                            if (c->resp.payload_size > 0) {
                                flb_plg_debug(ctx->ins,
                                              "Request failed and returned: \n%s",
                                              c->resp.payload);
                            }
                            else {
                                flb_plg_debug(ctx->ins, "Request failed");
                            }
                        }
                    }
                    else {
                        flb_plg_error(ctx->ins, "cannot send HTTP request");
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

static flb_sds_t azure_kusto_create_blob_id(struct flb_azure_kusto *ctx, flb_sds_t tag,
                                            size_t tag_len)
{
    flb_sds_t blob_id = NULL;
    struct flb_time tm;
    uint64_t ms;
    char *b64tag;
    size_t b64_len;

    flb_time_get(&tm);
    ms = ((tm.tm.tv_sec * 1000) + (tm.tm.tv_nsec / 1000000));

    b64tag = base64_encode(tag, tag_len, &b64_len);

    if (b64tag) {
        /* remove trailing '=' */
        while (b64_len && b64tag[b64_len - 1] == '=') {
            b64tag[b64_len - 1] = '\0';
            b64_len--;
        }

        blob_id = flb_sds_create_size(flb_sds_len(ctx->database_name) +
                                      flb_sds_len(ctx->table_name) + b64_len + 24);
        if (blob_id) {
            flb_sds_snprintf(&blob_id, flb_sds_alloc(blob_id), "flb__%s__%s__%s__%lu",
                             ctx->database_name, ctx->table_name, b64tag, ms);
        }
        else {
            flb_plg_error(ctx->ins, "cannot create blob id buffer");
        }

        flb_free(b64tag);
    }
    else {
        flb_plg_error(ctx->ins, "error encoding tag '%s' to base64", tag);
    }

    return blob_id;
}

int azure_kusto_queued_ingestion(struct flb_azure_kusto *ctx, flb_sds_t tag,
                                 size_t tag_len, flb_sds_t payload, size_t payload_size)
{
    int ret = -1;
    flb_sds_t blob_id;
    flb_sds_t blob_uri;

    /* flb__<db>__<table>__<b64tag>__<timestamp> */
    blob_id = azure_kusto_create_blob_id(ctx, tag, tag_len);

    if (blob_id) {
        blob_uri = azure_kusto_create_blob(ctx, blob_id, payload, payload_size);

        if (blob_uri) {
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
