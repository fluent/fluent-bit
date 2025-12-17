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
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_compression.h>

#include "azure_blob.h"
#include "azure_blob_conf.h"
#include "azure_blob_db.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int set_shared_key(struct flb_azure_blob *ctx)
{
    int s;
    int ret;
    size_t o_len = 0;

    s = flb_sds_len(ctx->shared_key);

    /* buffer for final hex key */
    ctx->decoded_sk = flb_malloc(s * 2);
    if (!ctx->decoded_sk) {
        return -1;
    }

    /* decode base64 */
    ret = flb_base64_decode(ctx->decoded_sk, s * 2,
                            &o_len,
                            (unsigned char *)ctx->shared_key,
                            flb_sds_len(ctx->shared_key));
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot decode shared_key");
        return -1;
    }

    ctx->decoded_sk_size = o_len;
    return 0;
}

static int find_map_entry_by_key(msgpack_object_map *map,
                                 char *key,
                                 size_t match_index,
                                 int case_insensitive)
{
    size_t  match_count;
    int     result;
    int     index;

    match_count = 0;

    for (index = 0 ; index < (int) map->size ; index++) {
        if (map->ptr[index].key.type == MSGPACK_OBJECT_STR) {
            if (case_insensitive) {
                result = strncasecmp(map->ptr[index].key.via.str.ptr,
                                     key,
                                     map->ptr[index].key.via.str.size);
            }
            else {
                result = strncmp(map->ptr[index].key.via.str.ptr,
                                 key,
                                 map->ptr[index].key.via.str.size);
            }

            if (result == 0) {
                if (match_count == match_index) {
                    return index;
                }

                match_count++;
            }
        }
    }

    return -1;
}

static int extract_map_string_entry_by_key(flb_sds_t *output,
                                           msgpack_object_map *map,
                                           char *key,
                                           size_t match_index,
                                           int case_insensitive)
{
    int index;
    int result;

    index = find_map_entry_by_key(map,
                                 key,
                                 match_index,
                                 case_insensitive);

    if (index == -1) {
        return -1;
    }

    if (map->ptr[index].val.type != MSGPACK_OBJECT_STR) {
        return -2;
    }

    if (*output == NULL) {
        *output = flb_sds_create_len(map->ptr[index].val.via.str.ptr,
                                     map->ptr[index].val.via.str.size);

        if (*output == NULL) {
            return -3;
        }
    }
    else {
        (*output)[0] = '\0';

        flb_sds_len_set(*output, 0);

        result = flb_sds_cat_safe(output,
                                  map->ptr[index].val.via.str.ptr,
                                  map->ptr[index].val.via.str.size);

        if (result != 0) {
            return -4;
        }
    }

    return 0;
}

static int flb_azure_blob_process_remote_configuration_payload(
                struct flb_azure_blob *context,
                char *payload,
                size_t payload_size)
{
    size_t               msgpack_body_length;
    msgpack_object_map  *configuration_map;
    msgpack_unpacked     unpacked_root;
    char                *msgpack_body;
    char                *value_backup;
    int                  root_type;
    size_t               offset;
    int                  result;

    result = flb_pack_json(payload,
                           payload_size,
                           &msgpack_body,
                           &msgpack_body_length,
                           &root_type,
                           NULL);

    if (result != 0) {
        flb_plg_error(context->ins,
                      "JSON to msgpack conversion error");

        result = -1;
    }
    else {
        msgpack_unpacked_init(&unpacked_root);

        offset = 0;
        result = msgpack_unpack_next(&unpacked_root,
                                     msgpack_body,
                                     msgpack_body_length,
                                     &offset);

        if (result != MSGPACK_UNPACK_SUCCESS) {
            flb_plg_error(context->ins, "corrupted msgpack data");

            result = -1;

            goto cleanup;
        }

        if (unpacked_root.data.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(context->ins, "unexpected root object type");

            result = -1;

            goto cleanup;
        }

        configuration_map = &unpacked_root.data.via.map;

        value_backup = context->endpoint;
        context->endpoint = NULL;

        result = extract_map_string_entry_by_key(&context->endpoint,
                                                 configuration_map,
                                                 "host", 0, FLB_TRUE);

        if (result != 0) {
            context->endpoint = value_backup;

            flb_plg_error(context->ins,
                            "endpoint extraction error : %d", result);

            goto cleanup;
        }

        context->endpoint_overriden_flag = FLB_TRUE;

        if (context->atype == AZURE_BLOB_AUTH_KEY) {
            value_backup = context->shared_key;
            context->shared_key = NULL;

            result = extract_map_string_entry_by_key(&context->shared_key,
                                                     configuration_map,
                                                     "shared_key", 0, FLB_TRUE);

            if (result != 0) {
                context->shared_key = value_backup;

                flb_plg_error(context->ins,
                              "neither sas_token nor shared_key " \
                              "could be extracted : %d", result);

                goto cleanup;
            }

            context->shared_key_overriden_flag = FLB_TRUE;
        }
        else if (context->atype == AZURE_BLOB_AUTH_SAS) {
            value_backup = context->sas_token;
            context->sas_token = NULL;

            result = extract_map_string_entry_by_key(&context->sas_token,
                                                    configuration_map,
                                                    "sas_token", 0, FLB_TRUE);

            if (result != 0) {
                context->sas_token = value_backup;

                flb_plg_error(context->ins,
                                "sas_token extraction error : %d", result);

                goto cleanup;
            }

            context->sas_token_overriden_flag = FLB_TRUE;
        }

        value_backup = context->container_name;
        context->container_name = NULL;

        result = extract_map_string_entry_by_key(&context->container_name,
                                                 configuration_map,
                                                 "container", 0, FLB_TRUE);

        if (result != 0) {
            context->container_name = value_backup;

            flb_plg_error(context->ins,
                            "container extraction error : %d", result);

            goto cleanup;
        }

        context->container_name_overriden_flag = FLB_TRUE;

        value_backup = context->path;
        context->path = NULL;

        result = extract_map_string_entry_by_key(&context->path,
                                                 configuration_map,
                                                 "path", 0, FLB_TRUE);

        if (result != 0) {
            context->path = value_backup;

            flb_plg_error(context->ins,
                            "path extraction error : %d", result);

            goto cleanup;
        }

        context->path_overriden_flag = FLB_TRUE;

cleanup:
        if (result != 0) {
            result = -1;
        }

        msgpack_unpacked_destroy(&unpacked_root);

        flb_free(msgpack_body);
    }

    return result;
}

static int flb_azure_blob_apply_remote_configuration(struct flb_azure_blob *context)
{
    int ret;
    size_t b_sent;
    struct flb_http_client *http_client;
    struct flb_connection *connection;
    struct flb_upstream *upstream;
    struct flb_tls *tls_context;
    char *scheme = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    uint16_t port_as_short;

    /* Parse and split URL */
    ret = flb_utils_url_split(context->configuration_endpoint_url,
                              &scheme, &host, &port, &uri);
    if (ret == -1) {
        flb_plg_error(context->ins,
                      "Invalid URL: %s",
                      context->configuration_endpoint_url);

        return -1;
    }

    if (port != NULL) {
        port_as_short = (uint16_t) strtoul(port, NULL, 10);
    }
    else {
        if (scheme != NULL) {
            if (strcasecmp(scheme, "https") == 0) {
                port_as_short = 443;
            }
            else {
                port_as_short = 80;
            }
        }
    }

    if (scheme != NULL) {
        flb_free(scheme);
        scheme = NULL;
    }

    if (port != NULL) {
        flb_free(port);
        port = NULL;
    }

    if (host == NULL || uri == NULL) {
        flb_plg_error(context->ins,
                      "Invalid URL: %s",
                      context->configuration_endpoint_url);

        if (host != NULL) {
            flb_free(host);
        }

        if (uri != NULL) {
            flb_free(uri);
        }

        return -2;
    }

    tls_context = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                 FLB_FALSE,
                                 FLB_FALSE,
                                 host,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL);

    if (tls_context == NULL) {
        flb_free(host);
        flb_free(uri);

        flb_plg_error(context->ins,
                      "TLS context creation errror");

        return -2;
    }

    upstream = flb_upstream_create_url(context->config,
                                       context->configuration_endpoint_url,
                                       FLB_IO_TCP,
                                       tls_context);

    if (upstream == NULL) {
        flb_tls_destroy(tls_context);
        flb_free(host);
        flb_free(uri);

        flb_plg_error(context->ins,
                      "Upstream creation errror");

        return -3;
    }

    flb_stream_disable_async_mode(&upstream->base);

    /* Get upstream connection */
    connection = flb_upstream_conn_get(upstream);
    if (connection == NULL) {
        flb_upstream_destroy(upstream);
        flb_tls_destroy(tls_context);
        flb_free(host);
        flb_free(uri);

        flb_plg_error(context->ins,
                      "cannot create connection");

        return -3;
    }

    /* Create HTTP client context */
    http_client = flb_http_client(connection,
                                  FLB_HTTP_GET,
                                  uri,
                                  NULL, 0,
                                  host,
                                  (int) port_as_short,
                                  NULL, 0);
    if (http_client == NULL) {
        flb_upstream_conn_release(connection);
        flb_upstream_destroy(upstream);
        flb_tls_destroy(tls_context);
        flb_free(host);
        flb_free(uri);

        flb_plg_error(context->ins,
                      "cannot create HTTP client");

        return -4;
    }

    flb_http_add_header(http_client,
                        "Accept",
                        strlen("Accept"),
                        "application/json",
                        16);

    /* User Agent */
    flb_http_add_header(http_client,
                        "User-Agent", 10,
                        "Fluent-Bit", 10);

    if (context->configuration_endpoint_username != NULL &&
        context->configuration_endpoint_password != NULL) {
        flb_http_basic_auth(http_client,
                            context->configuration_endpoint_username,
                            context->configuration_endpoint_password);
    }
    else if (context->configuration_endpoint_bearer_token != NULL) {
        flb_http_bearer_auth(http_client,
                             context->configuration_endpoint_bearer_token);
    }

    /* Send HTTP request */
    ret = flb_http_do(http_client, &b_sent);

    if (ret == -1) {
        flb_http_client_destroy(http_client);
        flb_upstream_conn_release(connection);
        flb_upstream_destroy(upstream);
        flb_tls_destroy(tls_context);
        flb_free(host);
        flb_free(uri);

        flb_plg_error(context->ins,
                      "Error sending configuration request");

        return -5;
    }

    if (http_client->resp.status == 200) {
        flb_plg_info(context->ins,
                     "Configuration retrieved successfully");

        ret = flb_azure_blob_process_remote_configuration_payload(
                context,
                http_client->resp.payload,
                http_client->resp.payload_size);

        if (ret != 0) {
            flb_plg_error(context->ins,
                          "Configuration payload processing error %d",
                          ret);

            flb_http_client_destroy(http_client);
            flb_upstream_conn_release(connection);
            flb_upstream_destroy(upstream);
            flb_tls_destroy(tls_context);
            flb_free(host);
            flb_free(uri);

            return -7;
        }

        flb_plg_info(context->ins,
                     "Configuration applied successfully");
    }
    else {
        if (http_client->resp.payload_size > 0) {
            flb_plg_error(context->ins,
                          "Configuration retrieval failed with status %i\n%s",
                          http_client->resp.status,
                          http_client->resp.payload);
        }
        else {
            flb_plg_error(context->ins,
                          "Configuration retrieval failed with status %i",
                          http_client->resp.status);
        }

        flb_http_client_destroy(http_client);
        flb_upstream_conn_release(connection);
        flb_upstream_destroy(upstream);
        flb_tls_destroy(tls_context);
        flb_free(host);
        flb_free(uri);

        return -6;
    }

    flb_http_client_destroy(http_client);
    flb_upstream_conn_release(connection);
    flb_upstream_destroy(upstream);
    flb_tls_destroy(tls_context);
    flb_free(host);
    flb_free(uri);

    return 0;
}

struct flb_azure_blob *flb_azure_blob_conf_create(struct flb_output_instance *ins,
                                                  struct flb_config *config)
{
    int ret;
    int port;
    int io_flags = 0;
    flb_sds_t tmp;
    struct flb_azure_blob *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_azure_blob));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->config = config;

    /* Set context */
    flb_output_set_context(ins, ctx);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);

        return NULL;
    }

    if (ctx->account_name == NULL) {
        flb_plg_error(ctx->ins, "'account_name' has not been set");
        return NULL;
    }

    if (ctx->configuration_endpoint_url != NULL) {
        ret = flb_azure_blob_apply_remote_configuration(ctx);

        if (ret != 0) {
            flb_free(ctx);

            return NULL;
        }
    }

    if (!ctx->container_name) {
        flb_plg_error(ctx->ins, "'container_name' has not been set");
        return NULL;
    }

    /* Set Auth type */
    tmp = (char *) flb_output_get_property("auth_type", ins);
    if (!tmp) {
        ctx->atype = AZURE_BLOB_AUTH_KEY;
    }
    else {
        if (strcasecmp(tmp, "key") == 0) {
            ctx->atype = AZURE_BLOB_AUTH_KEY;
        }
        else if (strcasecmp(tmp, "sas") == 0) {
            ctx->atype = AZURE_BLOB_AUTH_SAS;
        }
        else {
            flb_plg_error(ctx->ins, "invalid auth_type value '%s'", tmp);
            return NULL;
        }
    }
    if (ctx->atype == AZURE_BLOB_AUTH_KEY &&
        ctx->shared_key == NULL) {
        flb_plg_error(ctx->ins, "'shared_key' has not been set");
        return NULL;
    }

    if (ctx->atype == AZURE_BLOB_AUTH_SAS) {
        if (ctx->sas_token == NULL) {
            flb_plg_error(ctx->ins, "'sas_token' has not been set");
            return NULL;
        }
        if (ctx->sas_token[0] == '?') {
            ctx->sas_token++;
        }
    }

    /* If the shared key is set decode it */
    if (ctx->atype == AZURE_BLOB_AUTH_KEY &&
        ctx->shared_key != NULL) {
        ret = set_shared_key(ctx);
        if (ret == -1) {
            return NULL;
        }
    }

    /* Set Blob type */
    tmp = (char *) flb_output_get_property("blob_type", ins);
    if (!tmp) {
        ctx->btype = AZURE_BLOB_APPENDBLOB;
    }
    else {
        if (strcasecmp(tmp, "appendblob") == 0) {
            ctx->btype = AZURE_BLOB_APPENDBLOB;
        }
        else if (strcasecmp(tmp, "blockblob") == 0) {
            ctx->btype = AZURE_BLOB_BLOCKBLOB;
        }
        else {
            flb_plg_error(ctx->ins, "invalid blob_type value '%s'", tmp);
            return NULL;
        }
    }

    /* Check for invalid configuration: buffering enabled with appendblob */
    if (ctx->buffering_enabled == FLB_TRUE && ctx->btype == AZURE_BLOB_APPENDBLOB) {
        flb_plg_error(ctx->ins,
                      "buffering is not supported with 'appendblob' blob_type. "
                      "Please use 'blockblob' blob_type or disable buffering.");
        return NULL;
    }

    /* Compress payload over the wire */
    tmp = (char *) flb_output_get_property("compress", ins);
    ctx->compression = FLB_COMPRESSION_ALGORITHM_NONE;
    if (tmp) {
        if (strcasecmp(tmp, "gzip") == 0) {
            ctx->compression = FLB_COMPRESSION_ALGORITHM_GZIP;
        }
        else if (strcasecmp(tmp, "zstd") == 0) {
            ctx->compression = FLB_COMPRESSION_ALGORITHM_ZSTD;
        }
        else {
            flb_plg_error(ctx->ins, "invalid compress value '%s' (supported: gzip, zstd)", tmp);
            return NULL;
        }
    }

    /* Compress Blob: only availabel for blockblob type */
    if (ctx->compress_blob == FLB_TRUE && ctx->btype != AZURE_BLOB_BLOCKBLOB) {
        flb_plg_error(ctx->ins,
                      "the option 'compress_blob' is not compatible with 'appendblob' "
                      "blob_type");
        return NULL;
    }

    /*
     * Setting up the real endpoint:
     *
     * If the user provided a custom endpoint, just parse it. Here we need to
     * discover if a TLS connection is required, just use the protocol prefix.
     */
    if (ctx->endpoint) {
        if (strncmp(ctx->endpoint, "https", 5) == 0) {
            io_flags |= FLB_IO_TLS;
        }
        else {
            io_flags |= FLB_IO_TCP;
        }

        ctx->u = flb_upstream_create_url(config, ctx->endpoint,
                                         io_flags, ins->tls);
        if (!ctx->u) {
            flb_plg_error(ctx->ins, "invalid endpoint '%s'", ctx->endpoint);
            return NULL;
        }
        ctx->real_endpoint = flb_sds_create(ctx->endpoint);
    }
    else {
        ctx->real_endpoint = flb_sds_create_size(256);
        if (!ctx->real_endpoint) {
            flb_plg_error(ctx->ins, "cannot create endpoint");
            return NULL;
        }
        flb_sds_printf(&ctx->real_endpoint, "%s%s",
                       ctx->account_name,
                       AZURE_ENDPOINT_PREFIX);

        /* use TLS ? */
        if (ins->use_tls == FLB_TRUE) {
            port = 443;
            io_flags = FLB_IO_TLS;
        }
        else {
            port = 80;
            io_flags = FLB_IO_TCP;
        }

        ctx->u = flb_upstream_create(config, ctx->real_endpoint, port, io_flags,
                                     ins->tls);
        if (ctx->buffering_enabled ==  FLB_TRUE){
            flb_stream_disable_flags(&ctx->u->base, FLB_IO_ASYNC);
            ctx->u->base.net.io_timeout = ctx->io_timeout;
        }

        flb_plg_debug(ctx->ins, "async flag is %d", flb_stream_is_async(&ctx->u->base));
        if (!ctx->u) {
            flb_plg_error(ctx->ins, "cannot create upstream for endpoint '%s'",
                          ctx->real_endpoint);
            return NULL;
        }
    }
    flb_output_upstream_set(ctx->u, ins);

    /* Compose base uri */
    ctx->base_uri = flb_sds_create_size(256);
    if (!ctx->base_uri) {
        flb_plg_error(ctx->ins, "cannot create base_uri for endpoint '%s'",
                      ctx->real_endpoint);
        return NULL;
    }

    if (ctx->emulator_mode == FLB_TRUE) {
        flb_sds_printf(&ctx->base_uri, "/%s/", ctx->account_name);
    }
    else {
        flb_sds_printf(&ctx->base_uri, "/");
    }

    /* Prepare shared key buffer */
    if (ctx->atype == AZURE_BLOB_AUTH_KEY) {
        ctx->shared_key_prefix = flb_sds_create_size(256);
        if (!ctx->shared_key_prefix) {
            flb_plg_error(ctx->ins, "cannot create shared key prefix");
            return NULL;
        }
        flb_sds_printf(&ctx->shared_key_prefix, "SharedKey %s:", ctx->account_name);
    }

    /* Sanitize path: remove any ending slash */
    if (ctx->path) {
        if (ctx->path[flb_sds_len(ctx->path) - 1] == '/') {
            ctx->path[flb_sds_len(ctx->path) - 1] = '\0';
        }
    }

    /* database file for blob signal handling */
    if (ctx->database_file) {
        ctx->db = azb_db_open(ctx, ctx->database_file);
        if (!ctx->db) {
            return NULL;
        }
    }

    pthread_mutex_init(&ctx->file_upload_commit_file_parts, NULL);

    flb_plg_info(ctx->ins,
                 "account_name=%s, container_name=%s, blob_type=%s, emulator_mode=%s, endpoint=%s, auth_type=%s",
                 ctx->account_name, ctx->container_name,
                 ctx->btype == AZURE_BLOB_APPENDBLOB ? "appendblob" : "blockblob",
                 ctx->emulator_mode ? "yes" : "no",
                 ctx->real_endpoint ? ctx->real_endpoint : "no",
                 ctx->atype == AZURE_BLOB_AUTH_KEY ? "key" : "sas");
    return ctx;
}

void flb_azure_blob_conf_destroy(struct flb_azure_blob *ctx)
{

    if (ctx->endpoint_overriden_flag == FLB_TRUE) {
        flb_sds_destroy(ctx->endpoint);
        ctx->endpoint = NULL;
    }
    if (ctx->shared_key_overriden_flag == FLB_TRUE) {
        flb_sds_destroy(ctx->shared_key);
        ctx->shared_key = NULL;
    }
    if (ctx->sas_token_overriden_flag == FLB_TRUE) {
        flb_sds_destroy(ctx->sas_token);
        ctx->sas_token = NULL;
    }
    if (ctx->container_name_overriden_flag == FLB_TRUE) {
        flb_sds_destroy(ctx->container_name);
        ctx->container_name = NULL;
    }
    if (ctx->path_overriden_flag == FLB_TRUE) {
        flb_sds_destroy(ctx->path);
        ctx->path = NULL;
    }

    if (ctx->decoded_sk) {
        flb_free(ctx->decoded_sk);
    }

    if (ctx->base_uri) {
        flb_sds_destroy(ctx->base_uri);
    }

    if (ctx->real_endpoint) {
        flb_sds_destroy(ctx->real_endpoint);
    }

    if (ctx->shared_key_prefix) {
        flb_sds_destroy(ctx->shared_key_prefix);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }


    azb_db_close(ctx);
    flb_free(ctx);
}
