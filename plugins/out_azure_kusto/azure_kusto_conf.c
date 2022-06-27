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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_utils.h>

#include "azure_kusto.h"
#include "azure_kusto_conf.h"

static struct flb_upstream_node *flb_upstream_node_create_url(struct flb_azure_kusto *ctx,
                                                              struct flb_config *config,
                                                              const char *url)
{
    int ret;
    char *prot = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    char *tmp;
    struct flb_hash *kv;
    struct flb_upstream_node *node = NULL;
    int uri_length;
    int sas_length;

    /* Parse and split URL */
    ret = flb_utils_url_split(url, &prot, &host, &port, &uri);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "invalid URL: %s", url);
        goto upstream_node_create_url_out;
    }

    /* find sas token in query */
    tmp = strchr(uri, '?');
    if (!tmp) {
        flb_plg_error(ctx->ins, "uri has no sas token query: %s", uri);
        goto upstream_node_create_url_out;
    }
    uri_length = tmp - uri;
    sas_length = strnlen(tmp + 1, 256);

    /* kv that will hold base uri, and sas token */
    kv = flb_hash_create(FLB_HASH_EVICT_NONE, 2, 2);
    if (!kv) {
        flb_plg_error(ctx->ins, "error creating upstream node hash table");
        goto upstream_node_create_url_out;
    }

    ret = flb_hash_add(kv, AZURE_KUSTO_RESOURCE_UPSTREAM_URI, 3, uri, uri_length);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error storing resource uri");
        goto upstream_node_create_url_out;
    }

    ret = flb_hash_add(kv, AZURE_KUSTO_RESOURCE_UPSTREAM_SAS, 3, tmp + 1, sas_length);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error storing resource sas token");
        goto upstream_node_create_url_out;
    }

    node = flb_upstream_node_create(NULL, host, port, FLB_TRUE, ctx->ins->tls->verify,
                                    ctx->ins->tls->debug, ctx->ins->tls->vhost, NULL,
                                    NULL, NULL, NULL, NULL, kv, config);
    if (!node) {
        flb_plg_error(ctx->ins, "error creating resource upstream node");
        goto upstream_node_create_url_out;
    }

    flb_free(prot);
    flb_free(host);
    flb_free(port);
    flb_free(uri);

    return node;

upstream_node_create_url_out:
    if (prot) {
        flb_free(prot);
    }
    if (host) {
        flb_free(host);
    }
    if (port) {
        flb_free(port);
    }
    if (uri) {
        flb_free(uri);
    }
    if (kv) {
        flb_hash_destroy(kv);
    }
    return node;
}

static int flb_azure_kusto_resources_clear(struct flb_azure_kusto_resources *resources)
{
    if (!resources) {
        return -1;
    }

    if (resources->blob_ha) {
        flb_upstream_ha_destroy(resources->blob_ha);
        resources->blob_ha = NULL;
    }

    if (resources->queue_ha) {
        flb_upstream_ha_destroy(resources->queue_ha);
        resources->queue_ha = NULL;
    }

    if (resources->identity_token) {
        flb_sds_destroy(resources->identity_token);
        resources->identity_token = NULL;
    }

    resources->load_time = 0;

    return 0;
}

/**
 * Parses ".get ingestion resources" response into HA upstreams of the queue & blob
 * resources in the response.
 *
 * @param ctx       Pointer to the plugin's context
 * @param config    Pointer to the config
 * @param response  sds string containing the response body
 * @param blob_ha   Pointer to an HA upstream for the blob resources, that would be
 *                  allocated here.
 * @param queue_ha  Pointer to an HA upstream for the queue resources, that would be
 *                  allocated here.
 * @return int 0 on success, -1 on failure
 */
static int parse_storage_resources(struct flb_azure_kusto *ctx, struct flb_config *config,
                                   flb_sds_t response, struct flb_upstream_ha *blob_ha,
                                   struct flb_upstream_ha *queue_ha)
{
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;
    int tok_size = 100;
    int ret;
    int i;
    int blob_count = 0;
    int queue_count = 0;
    char *token_str;
    int token_str_len;
    int resource_type;
    struct flb_upstream_node *node;
    struct flb_upstream_ha *ha;
    flb_sds_t resource_uri = flb_sds_create(NULL);

    /* Response is a json in the form of
     * {
     *   "Tables": [
     *      {
     *          "TableName": "Table_0",
     *          "Columns": [...],
     *          "Rows": [
     *              [
     *                  ("TempStorage" | "SecuredReadyForAggregationQueue" |
     * "SuccessfulIngestionsQueue"  | "FailedIngestionsQueue" | "IngestionsStatusTable"),
     *                  <URI with SAS>
     *              ],
     *              ...
     *          ]
     *      }
     *   ]
     * }
     */

    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_plg_error(ctx->ins, "error allocating tokens");
        goto load_storage_resources_error;
    }

    ret = jsmn_parse(&parser, response, flb_sds_len(response), tokens, tok_size);
    if (ret <= 0) {
        flb_plg_error(ctx->ins, "error parsing JSON response: %s", response);
        goto load_storage_resources_error;
    }

    /* skip all tokens until we reach "Rows" */
    for (i = 0; i < ret - 1; i++) {
        t = &tokens[i];

        if (t->type != JSMN_STRING) {
            continue;
        }

        token_str = response + t->start;
        token_str_len = (t->end - t->start);

        /**
         * if we found the Rows key, skipping this token and the next one (key and
         * wrapping array value)
         */
        if (token_str_len == 4 && strncmp(token_str, "Rows", 4) == 0) {
            i += 2;
            break;
        }
    }

    /* iterating rows, each row will have 3 tokens: the array holding the column values,
     * the first value containing the resource type, and the second value containing the
     * resource uri */
    for (; i < ret; i++) {
        t = &tokens[i];

        /**
         * each token should be an array with 2 strings:
         * First will be the resource type (TempStorage, SecuredReadyForAggregationQueue,
         * etc...) Second will be the SAS URI
         */
        if (t->type != JSMN_ARRAY) {
            break;
        }

        /* move to the next token, first item in the array - resource type */
        i++;
        t = &tokens[i];
        if (t->type != JSMN_STRING) {
            break;
        }

        token_str = response + t->start;
        token_str_len = (t->end - t->start);

        flb_plg_debug(ctx->ins, "found resource of type: %.*s ", t->end - t->start,
                      response + t->start);

        if (token_str_len == 11 && strncmp(token_str, "TempStorage", 11) == 0) {
            resource_type = AZURE_KUSTO_RESOURCE_STORAGE;
        }
        else if (token_str_len == 31 &&
                 strncmp(token_str, "SecuredReadyForAggregationQueue", 31) == 0) {
            resource_type = AZURE_KUSTO_RESOURCE_QUEUE;
        }
        /* we don't care about other resources so we just skip the next token and move
           on to the next pair */
        else {
            i++;
            continue;
        }

        /* move to the next token, second item in the array - resource URI */
        i++;
        t = &tokens[i];

        if (t->type != JSMN_STRING) {
            break;
        }

        token_str = response + t->start;
        token_str_len = (t->end - t->start);

        resource_uri = flb_sds_copy(resource_uri, token_str, token_str_len);
        if (resource_type == AZURE_KUSTO_RESOURCE_QUEUE) {
            ha = queue_ha;
            queue_count++;
        }
        else {
            ha = blob_ha;
            blob_count++;
        }

        if (!ha) {
            flb_plg_error(ctx->ins, "error creating HA upstream");
            goto load_storage_resources_error;
        }

        node = flb_upstream_node_create_url(ctx, config, resource_uri);
        if (!node) {
            flb_plg_error(ctx->ins, "error creating HA upstream node");
            goto load_storage_resources_error;
        }

        flb_upstream_ha_node_add(ha, node);
    }

    if (!queue_count || !blob_count) {
        flb_plg_error(ctx->ins, "error parsing resources: missing resources");
        goto load_storage_resources_error;
    }

    flb_sds_destroy(resource_uri);
    flb_free(tokens);

    flb_plg_debug(ctx->ins, "parsed %d blob resources and %d queue resources", blob_count,
                  queue_count);

    return 0;

load_storage_resources_error:

    if (tokens) {
        flb_free(tokens);
    }

    if (resource_uri) {
        flb_sds_destroy(resource_uri);
    }

    return -1;
}

/**
 * Parses ".get kusto identity token" response and returns the token as an sds string
 *
 * @param ctx           Pointer to the plugin's context
 * @param response      sds string containing the response body
 * @return flb_sds_t    The parsed token
 */
static flb_sds_t parse_ingestion_identity_token(struct flb_azure_kusto *ctx,
                                                flb_sds_t response)
{
    flb_sds_t identity_token;
    int tok_size = 19;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;
    int ret;
    char *token_str;
    int token_str_len;

    /**
     * Response is a json in the form of
     * {
     *   "Tables": [
     *      {
     *          "TableName": "Table_0",
     *          "Columns": [{
     *              "ColumnName": "AuthorizationContext",
     *              "DataType": "String",
     *              "ColumnType": "string"
     *          }],
     *          "Rows": [
     *              [
     *                  <value>,
     *              ]
     *          ]
     *      }
     *   ]
     * }
     * i.e. only one row and one column is expected (exactly 13 tokens) and the value
     * should be the last
     */

    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_plg_error(ctx->ins, "error allocating tokens");
        return NULL;
    }

    ret = jsmn_parse(&parser, response, flb_sds_len(response), tokens, tok_size);
    if (ret <= 0) {
        flb_plg_error(ctx->ins, "error parsing JSON response: %s", response);
        flb_free(tokens);
        return NULL;
    }

    t = &tokens[tok_size - 1];
    if (t->type != JSMN_STRING) {
        flb_plg_error(ctx->ins, "unexpected JSON response: %s", response);
        flb_free(tokens);
        return NULL;
    }

    token_str = response + t->start;
    token_str_len = (t->end - t->start);

    identity_token = flb_sds_create_len(token_str, token_str_len);

    flb_plg_debug(ctx->ins, "parsed kusto identity token: '%s'", identity_token);

    flb_free(tokens);

    return identity_token;
}

int azure_kusto_load_ingestion_resources(struct flb_azure_kusto *ctx,
                                         struct flb_config *config)
{
    int ret;
    flb_sds_t response;
    flb_sds_t identity_token = NULL;
    struct flb_upstream_ha *blob_ha = NULL;
    struct flb_upstream_ha *queue_ha = NULL;
    time_t now;

    if (pthread_mutex_lock(&ctx->resources_mutex)) {
        flb_plg_error(ctx->ins, "error locking mutex");
        return -1;
    }

    now = time(NULL);

    /* check if we have all resources and they are not stale */
    if (ctx->resources->blob_ha && ctx->resources->queue_ha &&
        ctx->resources->identity_token &&
        now - ctx->resources->load_time < FLB_AZURE_KUSTO_RESOURCES_LOAD_INTERVAL_SEC) {
        if (pthread_mutex_unlock(&ctx->resources_mutex)) {
            flb_plg_error(ctx->ins, "error unlocking mutex");
            return -1;
        }

        flb_plg_debug(ctx->ins, "resources are already loaded and are not stale");
        return 0;
    }

    flb_plg_info(ctx->ins, "loading kusto ingestion resourcs");

    response = execute_ingest_csl_command(ctx, ".get ingestion resources");
    if (!response) {
        flb_plg_error(ctx->ins, "error getting ingestion storage resources");
        goto load_resources_error;
    }

    queue_ha = flb_upstream_ha_create("azure_kusto_queue_ha");
    blob_ha = flb_upstream_ha_create("azure_kusto_blob_ha");
    if (!queue_ha || !blob_ha) {
        flb_plg_error(ctx->ins, "error creating storage resources upstreams");
        goto load_resources_error;
    }

    ret = parse_storage_resources(ctx, config, response, blob_ha, queue_ha);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error parsing ingestion storage resources");
        goto load_resources_error;
    }

    flb_sds_destroy(response);

    response = execute_ingest_csl_command(ctx, ".get kusto identity token");
    if (!response) {
        flb_plg_error(ctx->ins, "error getting kusto identity token");
        goto load_resources_error;
    }

    identity_token = parse_ingestion_identity_token(ctx, response);
    if (!identity_token) {
        flb_plg_error(ctx->ins, "error parsing ingestion identity token");
        goto load_resources_error;
    }

    flb_sds_destroy(response);

    /* free old resources and point to newly allocated */
    flb_azure_kusto_resources_clear(ctx->resources);
    ctx->resources->blob_ha = blob_ha;
    ctx->resources->queue_ha = queue_ha;
    ctx->resources->identity_token = identity_token;
    ctx->resources->load_time = now;

    if (pthread_mutex_unlock(&ctx->resources_mutex)) {
        flb_plg_error(ctx->ins, "error unlocking mutex");
        return -1;
    }

    return 0;

load_resources_error:
    pthread_mutex_unlock(&ctx->resources_mutex);

    if (response) {
        flb_sds_destroy(response);
    }

    if (blob_ha) {
        flb_upstream_ha_destroy(blob_ha);
    }

    if (queue_ha) {
        flb_upstream_ha_destroy(queue_ha);
    }

    if (identity_token) {
        flb_sds_destroy(identity_token);
    }

    return -1;
}

static int flb_azure_kusto_resources_destroy(struct flb_azure_kusto_resources *resources)
{
    if (!resources) {
        return -1;
    }

    flb_azure_kusto_resources_clear(resources);

    flb_free(resources);

    return 0;
}

struct flb_azure_kusto *flb_azure_kusto_conf_create(struct flb_output_instance *ins,
                                                    struct flb_config *config)
{
    int ret;
    struct flb_azure_kusto *ctx;

    /* Allocate config context */
    ctx = flb_calloc(1, sizeof(struct flb_azure_kusto));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->config = config;

    ret = flb_output_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        flb_free(ctx);
        return NULL;
    }

    /* config: 'tenant_id' */
    if (ctx->tenant_id == NULL) {
        flb_plg_error(ctx->ins, "property 'tenant_id' is not defined.");
        flb_azure_kusto_conf_destroy(ctx);
        return NULL;
    }

    /* config: 'client_id' */
    if (ctx->client_id == NULL) {
        flb_plg_error(ctx->ins, "property 'client_id' is not defined");
        flb_azure_kusto_conf_destroy(ctx);
        return NULL;
    }

    /* config: 'client_secret' */
    if (ctx->client_secret == NULL) {
        flb_plg_error(ctx->ins, "property 'client_secret' is not defined");
        flb_azure_kusto_conf_destroy(ctx);
        return NULL;
    }

    /* config: 'ingestion_endpoint' */
    if (ctx->ingestion_endpoint == NULL) {
        flb_plg_error(ctx->ins, "property 'ingestion_endpoint' is not defined");
        flb_azure_kusto_conf_destroy(ctx);
        return NULL;
    }

    /* config: 'database_name' */
    if (ctx->database_name == NULL) {
        flb_plg_error(ctx->ins, "property 'database_name' is not defined");
        flb_azure_kusto_conf_destroy(ctx);
        return NULL;
    }

    /* config: 'table_name' */
    if (ctx->table_name == NULL) {
        flb_plg_error(ctx->ins, "property 'table_name' is not defined");
        flb_azure_kusto_conf_destroy(ctx);
        return NULL;
    }

    /* Create the auth URL */
    ctx->oauth_url = flb_sds_create_size(sizeof(FLB_MSAL_AUTH_URL_TEMPLATE) - 2 +
                                         flb_sds_len(ctx->tenant_id));
    if (!ctx->oauth_url) {
        flb_errno();
        flb_azure_kusto_conf_destroy(ctx);
        return NULL;
    }
    ctx->oauth_url =
        flb_sds_printf(&ctx->oauth_url, FLB_MSAL_AUTH_URL_TEMPLATE, ctx->tenant_id);

    ctx->resources = flb_calloc(1, sizeof(struct flb_azure_kusto_resources));
    if (!ctx->resources) {
        flb_errno();
        flb_azure_kusto_conf_destroy(ctx);
        return NULL;
    }

    flb_plg_info(ctx->ins, "endpoint='%s', database='%s', table='%s'",
                 ctx->ingestion_endpoint, ctx->database_name, ctx->table_name);

    return ctx;
}

int flb_azure_kusto_conf_destroy(struct flb_azure_kusto *ctx)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->oauth_url) {
        flb_sds_destroy(ctx->oauth_url);
        ctx->oauth_url = NULL;
    }

    if (ctx->o) {
        flb_oauth2_destroy(ctx->o);
        ctx->o = NULL;
    }

    if (ctx->resources) {
        flb_azure_kusto_resources_destroy(ctx->resources);
        ctx->resources = NULL;
    }

    flb_free(ctx);
    return 0;
}
