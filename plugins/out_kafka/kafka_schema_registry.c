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
#include <limits.h>

#ifdef FLB_HAVE_KAFKA_SCHEMA_REGISTRY
#include <jansson.h>
#endif

#include "kafka_config.h"

#ifdef FLB_HAVE_KAFKA_SCHEMA_REGISTRY

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

    ret = pthread_mutex_init(&ctx->schema_registry_lock, NULL);
    if (ret != 0) {
        return -1;
    }
    ctx->schema_registry_lock_initialized = FLB_TRUE;
    if (ctx->format == FLB_KAFKA_FMT_PROTOBUF && ctx->schema_registry_url == NULL) {
        flb_plg_error(ctx->ins, "format protobuf requires schema_registry_url");
        return -1;
    }

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

    if ((ctx->format == FLB_KAFKA_FMT_PROTOBUF || ctx->schema_str == NULL) &&
        ctx->schema_id <= 0 &&
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
        int schema_id)
{
    flb_sds_t uri;

    uri = flb_sds_create_size(flb_sds_len(endpoint->uri) + 32);
    if (uri == NULL) {
        return NULL;
    }

    uri = flb_sds_cat(uri, endpoint->uri, flb_sds_len(endpoint->uri));
    uri = flb_sds_printf(&uri, "/schemas/ids/%d", schema_id);

    return uri;
}

static flb_sds_t schema_registry_uri_by_subject(
        struct flb_kafka_schema_registry_endpoint *endpoint,
        const char *subject_name, const char *version)
{
    flb_sds_t uri;
    flb_sds_t subject;

    subject = flb_uri_encode(subject_name, strlen(subject_name));
    if (subject == NULL) {
        return NULL;
    }

    uri = flb_sds_create_size(flb_sds_len(endpoint->uri) +
                              flb_sds_len(subject) +
                              strlen(version) + 32);
    if (uri == NULL) {
        flb_sds_destroy(subject);
        return NULL;
    }

    uri = flb_sds_cat(uri, endpoint->uri, flb_sds_len(endpoint->uri));
    uri = flb_sds_cat(uri, "/subjects/", 10);
    uri = flb_sds_cat(uri, subject, flb_sds_len(subject));
    uri = flb_sds_cat(uri, "/versions/", 10);
    uri = flb_sds_cat(uri, version,
                      strlen(version));

    flb_sds_destroy(subject);

    return uri;
}

/* Validate endpoint documents without changing the cached schema. References do not
 * require an id, while root lookups by id may omit it in the response.
 */
static int schema_registry_validate_document(struct flb_out_kafka *ctx, json_t *root,
                                             int fallback_id, int require_id)
{
    int schema_id;
    const char *schema_type;
    json_t *id_value;
    json_t *schema_value;
    json_t *schema_type_value;
#ifdef FLB_HAVE_PROTOBUF_ENCODER
    size_t i;
    const char *name;
    const char *subject;
    json_t *references;
    json_t *reference;
    json_t *version;
#endif

    if (!json_is_object(root)) {
        return -1;
    }

    schema_type_value = json_object_get(root, "schemaType");
    if (schema_type_value != NULL) {
        if (!json_is_string(schema_type_value)) {
            flb_plg_error(ctx->ins, "Schema Registry schemaType must be a string");
            return -1;
        }
        schema_type = json_string_value(schema_type_value);
        if (strcasecmp(schema_type, ctx->format == FLB_KAFKA_FMT_PROTOBUF ?
                        "PROTOBUF" : "AVRO") != 0) {
            flb_plg_error(ctx->ins,
                          "unsupported Schema Registry schemaType '%s'",
                          schema_type);
            return -1;
        }
    }

    if (ctx->format == FLB_KAFKA_FMT_PROTOBUF && schema_type_value == NULL) {
        flb_plg_error(ctx->ins, "Protobuf requires Schema Registry schemaType PROTOBUF");
        return -1;
    }

    schema_value = json_object_get(root, "schema");
    if (!json_is_string(schema_value) || json_string_length(schema_value) == 0) {
        flb_plg_error(ctx->ins,
                      "Schema Registry response does not contain a schema string");
        return -1;
    }

    schema_id = fallback_id;
    id_value = json_object_get(root, "id");
    if (id_value != NULL) {
        if (!json_is_integer(id_value) || json_integer_value(id_value) <= 0 ||
            json_integer_value(id_value) > INT_MAX) {
            flb_plg_error(ctx->ins, "Schema Registry response contains an invalid schema id");
            return -1;
        }
        schema_id = (int) json_integer_value(id_value);
    }

    if (require_id && schema_id <= 0) {
        flb_plg_error(ctx->ins,
                      "Schema Registry response does not contain a valid schema id");
        return -1;
    }

#ifdef FLB_HAVE_PROTOBUF_ENCODER
    if (ctx->format == FLB_KAFKA_FMT_PROTOBUF) {
        references = json_object_get(root, "references");
        if (references != NULL) {
            if (!json_is_array(references)) {
                return -1;
            }
            json_array_foreach(references, i, reference) {
                name = json_string_value(json_object_get(reference, "name"));
                subject = json_string_value(json_object_get(reference, "subject"));
                version = json_object_get(reference, "version");
                if (name == NULL || name[0] == '\0' || subject == NULL || subject[0] == '\0' ||
                    strcmp(name, FLB_KAFKA_PROTOBUF_ROOT) == 0 || !json_is_integer(version) ||
                    json_integer_value(version) <= 0 || json_integer_value(version) > INT_MAX) {
                    return -1;
                }
            }
        }
    }
#endif
    return 0;
}

int flb_kafka_schema_registry_parse_response(struct flb_out_kafka *ctx,
                                             const char *payload,
                                             size_t payload_size)
{
    int schema_id;
    const char *schema;
    json_t *root;
    json_t *id_value;
    json_error_t error;
    flb_sds_t schema_copy;

    root = json_loadb(payload, payload_size, JSON_REJECT_DUPLICATES, &error);
    if (root == NULL) {
        flb_plg_error(ctx->ins, "cannot parse Schema Registry response: %s", error.text);
        return -1;
    }
    if (schema_registry_validate_document(ctx, root, ctx->schema_id, FLB_TRUE) != 0) {
        json_decref(root);
        return -1;
    }
    schema_id = ctx->schema_id;
    id_value = json_object_get(root, "id");
    if (id_value != NULL) {
        schema_id = (int) json_integer_value(id_value);
    }
    schema = json_string_value(json_object_get(root, "schema"));
    schema_copy = flb_sds_create(schema);
    if (schema_copy == NULL) {
        flb_errno();
        json_decref(root);
        return -1;
    }

    flb_sds_destroy(ctx->schema_str);
    ctx->schema_str = schema_copy;
    ctx->schema_id = schema_id;

    json_decref(root);

    return 0;
}

/* Fetches a bounded JSON document; callers own the returned reference. */
static int schema_registry_fetch(struct flb_out_kafka *ctx, const char *subject,
                                 const char *version, int schema_id, int require_id,
                                 json_t **document)
{
    int i;
    int ret;
    int index;
    size_t bytes;
    flb_sds_t uri;
    json_error_t error;
    struct flb_kafka_schema_registry_endpoint *endpoint;
    struct flb_connection *conn;
    struct flb_http_client *client;

    *document = NULL;
    index = ctx->schema_registry_endpoint_index;
    for (i = 0; i < ctx->schema_registry_endpoint_count; i++) {
        endpoint = schema_registry_endpoint_get(ctx, index);
        if (endpoint == NULL) {
            return FLB_ERROR;
        }
        if (subject != NULL) {
            uri = schema_registry_uri_by_subject(endpoint, subject, version);
        }
        else {
            uri = schema_registry_uri_by_id(endpoint, schema_id);
        }
        if (uri == NULL) {
            return FLB_ERROR;
        }
        conn = flb_upstream_conn_get(endpoint->upstream);
        if (conn == NULL) {
            flb_sds_destroy(uri);
            goto next_endpoint;
        }
        client = flb_http_client(conn, FLB_HTTP_GET, uri, NULL, 0,
                                 endpoint->host, endpoint->port, NULL, 0);
        if (client == NULL) {
            flb_upstream_conn_release(conn);
            flb_sds_destroy(uri);
            goto next_endpoint;
        }
        flb_http_buffer_size(client, 4 * 1024 * 1024);
        flb_http_add_header(client, "Accept", 6, FLB_KAFKA_SR_ACCEPT,
                            sizeof(FLB_KAFKA_SR_ACCEPT) - 1);
        flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);
        if (ctx->schema_registry_http_user != NULL) {
            flb_http_basic_auth(client, ctx->schema_registry_http_user,
                               ctx->schema_registry_http_passwd != NULL ?
                               ctx->schema_registry_http_passwd : "");
        }
        else if (ctx->schema_registry_bearer_token != NULL) {
            flb_http_bearer_auth(client, ctx->schema_registry_bearer_token);
        }
        ret = flb_http_do(client, &bytes);
        if (ret == 0 && client->resp.status == 200) {
            *document = json_loadb(client->resp.payload, client->resp.payload_size,
                                   JSON_REJECT_DUPLICATES, &error);
            if (schema_registry_validate_document(ctx, *document, schema_id, require_id) != 0) {
                json_decref(*document);
                *document = NULL;
                ret = FLB_RETRY;
            }
            else {
                ret = FLB_OK;
            }
        }
        else {
            flb_plg_warn(ctx->ins, "Schema Registry request failed: transport=%d HTTP=%d",
                         ret, client->resp.status);
            ret = FLB_RETRY;
        }
        flb_http_client_destroy(client);
        flb_upstream_conn_release(conn);
        flb_sds_destroy(uri);
        if (ret != FLB_RETRY) {
            ctx->schema_registry_endpoint_index = index;
            return ret;
        }
next_endpoint:
        index = (index + 1) % ctx->schema_registry_endpoint_count;
    }
    return FLB_RETRY;
}

#ifdef FLB_HAVE_PROTOBUF_ENCODER
struct schema_reference {
    const char *name;
    const char *subject;
    int version;
    int complete;
    json_t *document;
};

/* Documents remain alive until the entire graph has been compiled. */
struct schema_graph {
    struct schema_reference references[FLB_KAFKA_PROTOBUF_MAX_FILES];
    size_t count;
    struct flb_kafka_protobuf *protobuf;
};

static int schema_registry_load_references(struct flb_out_kafka *ctx,
                                           struct schema_graph *graph,
                                           json_t *document, size_t depth)
{
    int ret;
    size_t i;
    size_t j;
    int version;
    char version_text[16];
    const char *name;
    const char *subject;
    json_t *references;
    json_t *reference;
    json_t *value;
    json_t *schema;
    struct schema_reference *entry;

    if (depth > 32) {
        return FLB_ERROR;
    }
    references = json_object_get(document, "references");
    if (references == NULL) {
        return FLB_OK;
    }
    if (!json_is_array(references)) {
        return FLB_ERROR;
    }
    json_array_foreach(references, i, reference) {
        name = json_string_value(json_object_get(reference, "name"));
        subject = json_string_value(json_object_get(reference, "subject"));
        value = json_object_get(reference, "version");
        if (name == NULL || name[0] == '\0' || subject == NULL || subject[0] == '\0' ||
            strcmp(name, FLB_KAFKA_PROTOBUF_ROOT) == 0 || !json_is_integer(value) ||
            json_integer_value(value) <= 0 || json_integer_value(value) > INT_MAX) {
            return FLB_ERROR;
        }
        version = (int) json_integer_value(value);
        for (j = 0; j < graph->count; j++) {
            entry = &graph->references[j];
            if (strcmp(entry->name, name) == 0) {
                if (!entry->complete || strcmp(entry->subject, subject) != 0 ||
                    entry->version != version) {
                    return FLB_ERROR;
                }
                break;
            }
        }
        if (j < graph->count) {
            continue;
        }
        if (graph->count >= FLB_KAFKA_PROTOBUF_MAX_FILES - 1) {
            return FLB_ERROR;
        }
        entry = &graph->references[graph->count++];
        entry->name = name;
        entry->subject = subject;
        entry->version = version;
        snprintf(version_text, sizeof(version_text), "%d", version);
        ret = schema_registry_fetch(ctx, subject, version_text, 0, FLB_FALSE, &entry->document);
        if (ret != FLB_OK) {
            return ret;
        }
        schema = json_object_get(entry->document, "schema");
        ret = flb_kafka_protobuf_add(graph->protobuf, name, json_string_value(schema),
                                    json_string_length(schema));
        if (ret != 0) {
            return FLB_ERROR;
        }
        ret = schema_registry_load_references(ctx, graph, entry->document, depth + 1);
        if (ret != FLB_OK) {
            return ret;
        }
        entry->complete = FLB_TRUE;
    }
    return FLB_OK;
}

static int schema_registry_compile_protobuf(struct flb_out_kafka *ctx, json_t *document)
{
    int ret;
    size_t i;
    char error[512] = {0};
    struct schema_graph graph = {0};

    graph.protobuf = flb_kafka_protobuf_create();
    if (graph.protobuf == NULL) {
        return FLB_ERROR;
    }
    ret = flb_kafka_protobuf_add(graph.protobuf, FLB_KAFKA_PROTOBUF_ROOT,
                                ctx->schema_str, flb_sds_len(ctx->schema_str));
    if (ret != 0) {
        ret = FLB_ERROR;
        goto cleanup;
    }
    ret = schema_registry_load_references(ctx, &graph, document, 0);
    if (ret != FLB_OK) {
        goto cleanup;
    }
    ret = flb_kafka_protobuf_compile(graph.protobuf, ctx->protobuf_message, error, sizeof(error));
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot compile registered Protobuf schema: %s", error);
        ret = FLB_ERROR;
        goto cleanup;
    }
    ctx->protobuf = graph.protobuf;
    graph.protobuf = NULL;
    ret = FLB_OK;
cleanup:
    for (i = 0; i < graph.count; i++) {
        json_decref(graph.references[i].document);
    }
    flb_kafka_protobuf_destroy(graph.protobuf);
    return ret;
}
#endif

static int schema_registry_load(struct flb_out_kafka *ctx)
{
    int ret;
    char *payload;
    json_t *document;

    if (ctx->format != FLB_KAFKA_FMT_PROTOBUF && ctx->schema_str != NULL && ctx->schema_id > 0) {
        return FLB_OK;
    }
    if (ctx->schema_registry_endpoint_count == 0) {
        flb_plg_error(ctx->ins, "serializer requires a configured schema or Schema Registry URL");
        return FLB_ERROR;
    }
    ret = schema_registry_fetch(ctx, ctx->schema_registry_subject,
                                ctx->schema_registry_version, ctx->schema_id, FLB_TRUE, &document);
    if (ret != FLB_OK) {
        json_decref(document);
        return ret;
    }
    payload = json_dumps(document, JSON_COMPACT);
    if (payload == NULL) {
        json_decref(document);
        return FLB_ERROR;
    }
    ret = flb_kafka_schema_registry_parse_response(ctx, payload, strlen(payload));
    free(payload);
    if (ret != 0) {
        json_decref(document);
        return FLB_ERROR;
    }
    ret = FLB_OK;
#ifdef FLB_HAVE_PROTOBUF_ENCODER
    if (ctx->format == FLB_KAFKA_FMT_PROTOBUF) {
        ret = schema_registry_compile_protobuf(ctx, document);
    }
#endif
    json_decref(document);
    return ret;
}

int flb_kafka_schema_registry_resolve(struct flb_out_kafka *ctx)
{
    int ret;

    /* Never hold a thread mutex across asynchronous upstream I/O. */
    pthread_mutex_lock(&ctx->schema_registry_lock);
    if (ctx->schema_registry_ready) {
        pthread_mutex_unlock(&ctx->schema_registry_lock);
        return FLB_OK;
    }
    if (ctx->schema_registry_loading) {
        pthread_mutex_unlock(&ctx->schema_registry_lock);
        return FLB_RETRY;
    }
    ctx->schema_registry_loading = FLB_TRUE;
    pthread_mutex_unlock(&ctx->schema_registry_lock);

    ret = schema_registry_load(ctx);
    if (ret == FLB_ERROR) {
        flb_plg_error(ctx->ins, "cannot load Schema Registry schema or references");
    }

    pthread_mutex_lock(&ctx->schema_registry_lock);
    ctx->schema_registry_ready = ret == FLB_OK;
    ctx->schema_registry_loading = FLB_FALSE;
    pthread_mutex_unlock(&ctx->schema_registry_lock);
    return ret;
}

void flb_kafka_schema_registry_destroy(struct flb_out_kafka *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_kafka_schema_registry_endpoint *endpoint;

#ifdef FLB_HAVE_PROTOBUF_ENCODER
    flb_kafka_protobuf_destroy(ctx->protobuf);
#endif
    if (ctx->schema_registry_lock_initialized) {
        pthread_mutex_destroy(&ctx->schema_registry_lock);
    }

    mk_list_foreach_safe(head, tmp, &ctx->schema_registry_endpoints) {
        endpoint = mk_list_entry(head,
                                 struct flb_kafka_schema_registry_endpoint,
                                 _head);
        mk_list_del(&endpoint->_head);
        schema_registry_endpoint_destroy(endpoint);
    }
}

#endif
