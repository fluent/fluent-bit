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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_utils.h>

#ifdef FLB_HAVE_AVRO_ENCODER
#include <jansson.h>
#endif

#include "kafka_config.h"

#ifdef FLB_HAVE_AVRO_ENCODER

#define FLB_KAFKA_SR_ACCEPT "application/vnd.schemaregistry.v1+json, application/json"

static int schema_registry_set_base_uri(struct flb_kafka_schema_registry_endpoint *endpoint,
                                        char *uri)
{
    size_t len;

    if (uri == NULL || uri[0] == '\0' || strcmp(uri, "/") == 0) {
        endpoint->uri = flb_sds_create("");
        return endpoint->uri == NULL ? -1 : 0;
    }

    endpoint->uri = flb_sds_create(uri);
    if (endpoint->uri == NULL) {
        return -1;
    }

    len = flb_sds_len(endpoint->uri);
    if (len > 1 && endpoint->uri[len - 1] == '/') {
        flb_sds_len_set(endpoint->uri, len - 1);
        endpoint->uri[len - 1] = '\0';
    }

    return 0;
}

static void schema_registry_endpoint_destroy(struct flb_kafka_schema_registry_endpoint *endpoint)
{
    if (endpoint == NULL) {
        return;
    }

    flb_sds_destroy(endpoint->host);
    flb_sds_destroy(endpoint->uri);

    if (endpoint->upstream != NULL) {
        flb_upstream_destroy(endpoint->upstream);
    }

    flb_free(endpoint);
}

static int schema_registry_endpoint_create(struct flb_out_kafka *ctx,
                                           struct flb_config *config,
                                           char *url)
{
    int ret;
    int port;
    int io_flags;
    char *protocol;
    char *host;
    char *port_str;
    char *uri;
    struct flb_kafka_schema_registry_endpoint *endpoint;

    protocol = NULL;
    host = NULL;
    port_str = NULL;
    uri = NULL;

    endpoint = flb_calloc(1, sizeof(struct flb_kafka_schema_registry_endpoint));
    if (endpoint == NULL) {
        flb_errno();
        return -1;
    }

    ret = flb_utils_url_split(url, &protocol, &host, &port_str, &uri);
    if (ret == -1 || protocol == NULL || host == NULL) {
        flb_plg_error(ctx->ins, "invalid schema_registry_url '%s'", url);
        ret = -1;
        goto cleanup;
    }

    if (strcasecmp(protocol, "http") == 0) {
        port = port_str != NULL ? atoi(port_str) : 80;
        io_flags = FLB_IO_TCP;
    }
    else if (strcasecmp(protocol, "https") == 0) {
#ifdef FLB_HAVE_TLS
        port = port_str != NULL ? atoi(port_str) : 443;
        io_flags = FLB_IO_TLS;
#else
        flb_plg_error(ctx->ins, "schema_registry_url requires TLS support");
        ret = -1;
        goto cleanup;
#endif
    }
    else {
        flb_plg_error(ctx->ins, "unsupported schema_registry_url protocol '%s'",
                      protocol);
        ret = -1;
        goto cleanup;
    }

    if (port <= 0) {
        flb_plg_error(ctx->ins, "invalid schema_registry_url port");
        ret = -1;
        goto cleanup;
    }

    endpoint->host = flb_sds_create(host);
    if (endpoint->host == NULL) {
        flb_errno();
        ret = -1;
        goto cleanup;
    }

    ret = schema_registry_set_base_uri(endpoint, uri);
    if (ret == -1) {
        flb_errno();
        goto cleanup;
    }

    endpoint->port = port;
    endpoint->upstream = flb_upstream_create(config,
                                             endpoint->host,
                                             port,
                                             io_flags,
                                             ctx->ins->tls);
    if (endpoint->upstream == NULL) {
        flb_plg_error(ctx->ins, "cannot create Schema Registry upstream");
        ret = -1;
        goto cleanup;
    }

    flb_output_upstream_set(endpoint->upstream, ctx->ins);
    mk_list_add(&endpoint->_head, &ctx->schema_registry_endpoints);
    ctx->schema_registry_endpoint_count++;
    endpoint = NULL;
    ret = 0;

cleanup:
    schema_registry_endpoint_destroy(endpoint);
    flb_free(protocol);
    flb_free(host);
    flb_free(port_str);
    flb_free(uri);

    return ret;
}

int flb_kafka_schema_registry_configure(struct flb_out_kafka *ctx,
                                        struct flb_config *config)
{
    int ret;
    size_t url_len;
    char *url;
    char *comma;
    flb_sds_t url_copy;

    url_copy = NULL;

    if (ctx->schema_registry_framing != NULL &&
        strcasecmp(ctx->schema_registry_framing, "cp1") != 0) {
        flb_plg_error(ctx->ins,
                      "unsupported Schema Registry serializer framing '%s': "
                      "only cp1 is supported",
                      ctx->schema_registry_framing);
        return -1;
    }

    if (ctx->schema_registry_url == NULL) {
        return 0;
    }

    url = ctx->schema_registry_url;
    while (*url != '\0') {
        while (*url == ' ') {
            url++;
        }

        comma = strchr(url, ',');
        if (comma != NULL) {
            url_len = comma - url;
        }
        else {
            url_len = strlen(url);
        }

        while (url_len > 0 && url[url_len - 1] == ' ') {
            url_len--;
        }

        if (url_len > 0) {
            url_copy = flb_sds_create_len(url, url_len);
            if (url_copy == NULL) {
                flb_errno();
                return -1;
            }

            ret = schema_registry_endpoint_create(ctx, config, url_copy);
            flb_sds_destroy(url_copy);
            url_copy = NULL;
            if (ret == -1) {
                return -1;
            }
        }

        if (comma == NULL) {
            break;
        }
        url = comma + 1;
    }

    if (ctx->schema_registry_endpoint_count == 0) {
        flb_plg_error(ctx->ins, "schema_registry_url does not contain a valid URL");
        return -1;
    }

    if (ctx->schema_registry_version == NULL) {
        ctx->schema_registry_version = flb_sds_create("latest");
        if (ctx->schema_registry_version == NULL) {
            flb_errno();
            return -1;
        }
    }

    if (ctx->avro_fields.schema_str == NULL &&
        ctx->avro_fields.schema_id <= 0 &&
        ctx->schema_registry_subject == NULL) {
        flb_plg_error(ctx->ins,
                      "schema_registry_url requires schema_id or schema_registry_subject");
        return -1;
    }

    return 0;
}

static struct flb_kafka_schema_registry_endpoint *schema_registry_endpoint_get(
        struct flb_out_kafka *ctx, int index)
{
    int i;
    struct mk_list *head;
    struct flb_kafka_schema_registry_endpoint *endpoint;

    i = 0;
    mk_list_foreach(head, &ctx->schema_registry_endpoints) {
        endpoint = mk_list_entry(head,
                                 struct flb_kafka_schema_registry_endpoint,
                                 _head);
        if (i == index) {
            return endpoint;
        }
        i++;
    }

    return NULL;
}

static flb_sds_t schema_registry_uri_by_id(
        struct flb_kafka_schema_registry_endpoint *endpoint,
        struct flb_out_kafka *ctx)
{
    flb_sds_t uri;

    uri = flb_sds_create_size(flb_sds_len(endpoint->uri) + 32);
    if (uri == NULL) {
        return NULL;
    }

    uri = flb_sds_cat(uri, endpoint->uri, flb_sds_len(endpoint->uri));
    uri = flb_sds_printf(&uri, "/schemas/ids/%d", ctx->avro_fields.schema_id);

    return uri;
}

static flb_sds_t schema_registry_uri_by_subject(
        struct flb_kafka_schema_registry_endpoint *endpoint,
        struct flb_out_kafka *ctx)
{
    flb_sds_t uri;
    flb_sds_t subject;

    subject = flb_uri_encode(ctx->schema_registry_subject,
                             flb_sds_len(ctx->schema_registry_subject));
    if (subject == NULL) {
        return NULL;
    }

    uri = flb_sds_create_size(flb_sds_len(endpoint->uri) +
                              flb_sds_len(subject) +
                              flb_sds_len(ctx->schema_registry_version) + 32);
    if (uri == NULL) {
        flb_sds_destroy(subject);
        return NULL;
    }

    uri = flb_sds_cat(uri, endpoint->uri, flb_sds_len(endpoint->uri));
    uri = flb_sds_cat(uri, "/subjects/", 10);
    uri = flb_sds_cat(uri, subject, flb_sds_len(subject));
    uri = flb_sds_cat(uri, "/versions/", 10);
    uri = flb_sds_cat(uri, ctx->schema_registry_version,
                      flb_sds_len(ctx->schema_registry_version));

    flb_sds_destroy(subject);

    return uri;
}

int flb_kafka_schema_registry_parse_response(struct flb_out_kafka *ctx,
                                             const char *payload,
                                             size_t payload_size)
{
    int schema_id;
    const char *schema;
    const char *schema_type;
    json_t *root;
    json_t *id_value;
    json_t *schema_value;
    json_t *schema_type_value;
    json_error_t error;
    flb_sds_t schema_copy;

    root = json_loadb(payload, payload_size, 0, &error);
    if (root == NULL) {
        flb_plg_error(ctx->ins, "cannot parse Schema Registry response: %s",
                      error.text);
        return -1;
    }

    schema_type_value = json_object_get(root, "schemaType");
    if (schema_type_value != NULL && json_is_string(schema_type_value)) {
        schema_type = json_string_value(schema_type_value);
        if (strcasecmp(schema_type, "AVRO") != 0) {
            flb_plg_error(ctx->ins,
                          "unsupported Schema Registry schemaType '%s'",
                          schema_type);
            json_decref(root);
            return -1;
        }
    }

    schema_value = json_object_get(root, "schema");
    if (schema_value == NULL || !json_is_string(schema_value)) {
        flb_plg_error(ctx->ins,
                      "Schema Registry response does not contain a schema string");
        json_decref(root);
        return -1;
    }

    schema_id = ctx->avro_fields.schema_id;
    id_value = json_object_get(root, "id");
    if (id_value != NULL && json_is_integer(id_value)) {
        schema_id = (int) json_integer_value(id_value);
    }

    if (schema_id <= 0) {
        flb_plg_error(ctx->ins,
                      "Schema Registry response does not contain a valid schema id");
        json_decref(root);
        return -1;
    }

    schema = json_string_value(schema_value);
    schema_copy = flb_sds_create(schema);
    if (schema_copy == NULL) {
        flb_errno();
        json_decref(root);
        return -1;
    }

    flb_sds_destroy(ctx->avro_fields.schema_str);
    ctx->avro_fields.schema_str = schema_copy;
    ctx->avro_fields.schema_id = schema_id;

    json_decref(root);

    return 0;
}

int flb_kafka_schema_registry_resolve(struct flb_out_kafka *ctx)
{
    int i;
    int ret;
    int index;
    size_t bytes;
    flb_sds_t uri;
    struct flb_kafka_schema_registry_endpoint *endpoint;
    struct flb_connection *conn;
    struct flb_http_client *client;

    if (ctx->avro_fields.schema_str != NULL &&
        ctx->avro_fields.schema_id > 0) {
        return FLB_OK;
    }

    if (ctx->schema_registry_endpoint_count == 0) {
        flb_plg_error(ctx->ins,
                      "format avro requires schema_str and schema_id or schema_registry_url");
        return FLB_ERROR;
    }

    ret = FLB_RETRY;
    index = ctx->schema_registry_endpoint_index;
    for (i = 0; i < ctx->schema_registry_endpoint_count; i++) {
        endpoint = schema_registry_endpoint_get(ctx, index);
        if (endpoint == NULL) {
            index = 0;
            endpoint = schema_registry_endpoint_get(ctx, index);
            if (endpoint == NULL) {
                return FLB_ERROR;
            }
        }

        if (ctx->schema_registry_subject != NULL) {
            uri = schema_registry_uri_by_subject(endpoint, ctx);
        }
        else {
            uri = schema_registry_uri_by_id(endpoint, ctx);
        }

        if (uri == NULL) {
            flb_errno();
            return FLB_ERROR;
        }

        conn = flb_upstream_conn_get(endpoint->upstream);
        if (conn == NULL) {
            flb_sds_destroy(uri);
            ret = FLB_RETRY;
            goto next_endpoint;
        }

        client = flb_http_client(conn, FLB_HTTP_GET, uri, NULL, 0,
                                 endpoint->host, endpoint->port, NULL, 0);
        if (client == NULL) {
            flb_upstream_conn_release(conn);
            flb_sds_destroy(uri);
            ret = FLB_RETRY;
            goto next_endpoint;
        }

        flb_http_add_header(client, "Accept", 6,
                            FLB_KAFKA_SR_ACCEPT,
                            sizeof(FLB_KAFKA_SR_ACCEPT) - 1);
        flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);

        if (ctx->schema_registry_http_user != NULL) {
            flb_http_basic_auth(client,
                                ctx->schema_registry_http_user,
                                ctx->schema_registry_http_passwd != NULL ?
                                ctx->schema_registry_http_passwd : "");
        }
        else if (ctx->schema_registry_bearer_token != NULL) {
            flb_http_bearer_auth(client, ctx->schema_registry_bearer_token);
        }

        ret = flb_http_do(client, &bytes);
        if (ret != 0) {
            flb_plg_warn(ctx->ins,
                         "Schema Registry request to '%s' failed: %i",
                         endpoint->host, ret);
            ret = FLB_RETRY;
            flb_http_client_destroy(client);
            flb_upstream_conn_release(conn);
            flb_sds_destroy(uri);
            goto next_endpoint;
        }

        if (client->resp.status < 200 || client->resp.status > 299) {
            flb_plg_warn(ctx->ins,
                         "Schema Registry request to '%s' returned HTTP status %i",
                         endpoint->host, client->resp.status);
            ret = FLB_RETRY;
            flb_http_client_destroy(client);
            flb_upstream_conn_release(conn);
            flb_sds_destroy(uri);
            goto next_endpoint;
        }

        ret = flb_kafka_schema_registry_parse_response(ctx,
                                                       client->resp.payload,
                                                       client->resp.payload_size);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(conn);
        flb_sds_destroy(uri);

        if (ret != 0) {
            return FLB_ERROR;
        }

        ctx->schema_registry_endpoint_index =
            (index + 1) % ctx->schema_registry_endpoint_count;
        flb_plg_info(ctx->ins,
                     "loaded Avro schema id %d from Schema Registry '%s'",
                     ctx->avro_fields.schema_id, endpoint->host);

        return FLB_OK;

    next_endpoint:
        index = (index + 1) % ctx->schema_registry_endpoint_count;
    }

    ctx->schema_registry_endpoint_index = index;

    return ret;
}

void flb_kafka_schema_registry_destroy(struct flb_out_kafka *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_kafka_schema_registry_endpoint *endpoint;

    mk_list_foreach_safe(head, tmp, &ctx->schema_registry_endpoints) {
        endpoint = mk_list_entry(head,
                                 struct flb_kafka_schema_registry_endpoint,
                                 _head);
        mk_list_del(&endpoint->_head);
        schema_registry_endpoint_destroy(endpoint);
    }
}

#endif
