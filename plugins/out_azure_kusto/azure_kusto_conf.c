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

#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_utils.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <fluent-bit/flb_time.h>

#include "azure_kusto.h"
#include "azure_kusto_conf.h"
#include "azure_msiauth.h"

/* Constants for PCG random number generator */
#define PCG_DEFAULT_MULTIPLIER_64  6364136223846793005ULL
#define PCG_DEFAULT_INCREMENT_64   1442695040888963407ULL

/* PCG random number generator state */
typedef struct { uint64_t state;  uint64_t inc; } pcg32_random_t;

static struct flb_upstream_node *flb_upstream_node_create_url(struct flb_azure_kusto *ctx,
                                                              struct flb_config *config,
                                                              const char *url)
{
    int ret;
    char *prot = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    flb_sds_t sds_host = NULL;
    flb_sds_t sds_port = NULL;
    char *tmp;
    struct flb_hash_table *kv = NULL;
    struct flb_upstream_node *node = NULL;
    int uri_length;
    int sas_length;

    /* Parse and split URL */
    ret = flb_utils_url_split(url, &prot, &host, &port, &uri);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "invalid URL: %s", url);
        return NULL;
    }

    /* find sas token in query */
    tmp = strchr(uri, '?');

    if (tmp) {
        uri_length = tmp - uri;
        sas_length = strnlen(tmp + 1, 256);

        /* kv that will hold base uri, and sas token */
        kv = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 2, 2);

        if (kv) {
            ret = flb_hash_table_add(kv, AZURE_KUSTO_RESOURCE_UPSTREAM_URI, 3, uri, uri_length);

            if (ret != -1) {
                ret = flb_hash_table_add(kv, AZURE_KUSTO_RESOURCE_UPSTREAM_SAS, 3, tmp + 1,
                                   sas_length);

                if (ret != -1) {
                    /* if any/all of these creations would fail the node creation will fail and cleanup */
                    sds_host = flb_sds_create(host);
                    sds_port = flb_sds_create(port);

                    node = flb_upstream_node_create(
                        NULL, sds_host, sds_port, FLB_TRUE, ctx->ins->tls->verify,
                        ctx->ins->tls->verify_hostname,
                        ctx->ins->tls->debug, ctx->ins->tls->vhost, NULL, NULL, NULL,
                        NULL, NULL, kv, config);

                    if (!node) {
                        flb_plg_error(ctx->ins, "error creating resource upstream node");
                    }
                }
                else {
                    flb_plg_error(ctx->ins, "error storing resource sas token");
                }
            }
            else {
                flb_plg_error(ctx->ins, "error storing resource uri");
            }

            /* avoid destorying if function is successful */
            if (!node) {
                flb_hash_table_destroy(kv);
            }
        }
        else {
            flb_plg_error(ctx->ins, "error creating upstream node hash table");
        }
    }
    else {
        flb_plg_error(ctx->ins, "uri has no sas token query: %s", uri);
    }

    flb_free(prot);
    flb_free(host);
    flb_free(port);
    flb_free(uri);

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

    /* Also clean up any old resources pending destruction */
    if (resources->old_blob_ha) {
        flb_upstream_ha_destroy(resources->old_blob_ha);
        resources->old_blob_ha = NULL;
    }

    if (resources->old_queue_ha) {
        flb_upstream_ha_destroy(resources->old_queue_ha);
        resources->old_queue_ha = NULL;
    }

    if (resources->old_identity_token) {
        flb_sds_destroy(resources->old_identity_token);
        resources->old_identity_token = NULL;
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
    jsmntok_t *t = NULL;
    jsmntok_t *tokens = NULL;
    int ret = -1;
    int i;
    int blob_count = 0;
    int queue_count = 0;
    char *token_str;
    int token_str_len;
    int resource_type;
    struct flb_upstream_node *node;
    struct flb_upstream_ha *ha;
    flb_sds_t resource_uri = NULL;

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

    resource_uri = flb_sds_create(NULL);
    if (!resource_uri) {
        flb_plg_error(ctx->ins, "error allocating resource uri buffer");
        goto cleanup;
    }

    jsmn_init(&parser);

    /* Dynamically allocate memory for tokens based on response length */
    tokens = flb_calloc(1, sizeof(jsmntok_t) * (flb_sds_len(response)));

    if (!tokens) {
        flb_plg_error(ctx->ins, "error allocating tokens");
        goto cleanup;
    }

    if (tokens) {
        ret = jsmn_parse(&parser, response, flb_sds_len(response), tokens, flb_sds_len(response));

        if (ret > 0) {
            /* skip all tokens until we reach "Rows" */
            for (i = 0; i < ret - 1; i++) {
                jsmntok_t *t = &tokens[i];

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

            /* iterating rows, each row will have 3 tokens: the array holding the column
             * values, the first value containing the resource type, and the second value
             * containing the resource uri */
            for (; i < ret; i++) {
                jsmntok_t *t = &tokens[i];

                /**
                 * each token should be an array with 2 strings:
                 * First will be the resource type (TempStorage,
                 * SecuredReadyForAggregationQueue, etc...) Second will be the SAS URI
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

                flb_plg_debug(ctx->ins, "found resource of type: %.*s ",
                              t->end - t->start, response + t->start);

                if (token_str_len == 11 && strncmp(token_str, "TempStorage", 11) == 0) {
                    resource_type = AZURE_KUSTO_RESOURCE_STORAGE;
                }
                else if (token_str_len == 31 &&
                         strncmp(token_str, "SecuredReadyForAggregationQueue", 31) == 0) {
                    resource_type = AZURE_KUSTO_RESOURCE_QUEUE;
                }
                    /* we don't care about other resources so we just skip the next token and
                       move on to the next pair */
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
                if (!resource_uri) {
                    flb_plg_error(ctx->ins, "error copying resource URI");
                    ret = -1;
                    goto cleanup;
                }
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
                    ret = -1;
                    goto cleanup;
                }

                node = flb_upstream_node_create_url(ctx, config, resource_uri);

                if (!node) {
                    flb_plg_error(ctx->ins, "error creating HA upstream node");
                    ret = -1;
                    goto cleanup;
                }

                flb_upstream_ha_node_add(ha, node);
            }

            if (ret != -1) {
                if (queue_count > 0 && blob_count > 0) {
                    flb_plg_debug(ctx->ins,
                                  "parsed %d blob resources and %d queue resources",
                                  blob_count, queue_count);
                    ret = 0;
                }
                else {
                    flb_plg_error(ctx->ins, "error parsing resources: missing resources");
                    ret = -1;
                    goto cleanup;
                }
            }
        }
        else {
            flb_plg_error(ctx->ins, "error parsing JSON response: %s", response);
            ret = -1;
            goto cleanup;
        }
    }
    else {
        flb_plg_error(ctx->ins, "error allocating tokens");
        ret = -1;
        goto cleanup;
    }

    cleanup:
    if (resource_uri) {
        flb_sds_destroy(resource_uri);
    }
    if (tokens) {
        flb_free(tokens);
    }

    return ret;
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
    flb_sds_t identity_token = NULL;
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
    if (ret > 0) {
        t = &tokens[tok_size - 1];

        if (t->type == JSMN_STRING) {
            t = &tokens[tok_size - 1];
            token_str = response + t->start;
            token_str_len = (t->end - t->start);

            identity_token = flb_sds_create_len(token_str, token_str_len);

            if (identity_token) {
                flb_plg_debug(ctx->ins, "parsed kusto identity token ");
            }
            else {
                flb_plg_error(ctx->ins, "error parsing kusto identity token");
            }
        }
        else {
            flb_plg_error(ctx->ins, "unexpected JSON response: %s", response);
        }
    }
    else {
        flb_plg_error(ctx->ins, "error parsing JSON response: %s", response);
    }

    flb_free(tokens);

    return identity_token;
}

/* PCG random number generator function */
static uint32_t pcg32_random_r(pcg32_random_t* rng) {
    uint64_t oldstate = rng->state;
    rng->state = oldstate * PCG_DEFAULT_MULTIPLIER_64 + rng->inc;
    uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    uint32_t rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

/**
 * Generates a random integer within a specified range to adjust the refresh interval
 * for Azure Kusto ingestion resources. This helps in distributing the load evenly
 * by adding variability to the refresh timing, thus preventing spikes in demand.
 *
 * The method combines various sources of entropy including environment variables,
 * current time, and additional random bytes to generate a robust random number.
 *
 * Inputs:
 * - Environment variables: HOSTNAME and CLUSTER_NAME, which are used to identify
 *   the pod and cluster respectively. Defaults are used if these are not set.
 * - Current time with high precision is obtained to ensure uniqueness.
 *
 * Outputs:
 * - Returns a random integer in the range of -600,000 to +3,600,000.
 * - In case of failure in generating random bytes, the method returns -1.
 *
 * The method utilizes SHA256 hashing and additional entropy from OpenSSL's
 * RAND_bytes to ensure randomness. The PCG (Permuted Congruential Generator)
 * algorithm is used for generating the final random number.
 */
int azure_kusto_generate_random_integer() {
    int i;
    /* Get environment variables or use default values */
    const char *pod_id = getenv("HOSTNAME");
    const char *cluster_name = getenv("CLUSTER_NAME");
    pod_id = pod_id ? pod_id : "default_pod_id";
    cluster_name = cluster_name ? cluster_name : "default_cluster_name";

    /* Get current time with high precision */
    struct flb_time tm_now;
    flb_time_get(&tm_now);
    uint64_t current_time = flb_time_to_nanosec(&tm_now);

    /* Generate additional random entropy */
    unsigned char entropy[32];
    if (RAND_bytes(entropy, sizeof(entropy)) != 1) {
        fprintf(stderr, "Error generating random bytes\n");
        return -1;
    }

    /* Combine all sources of entropy into a single string */
    char combined[1024];
    snprintf(combined, sizeof(combined), "%s%s%llu%p",
             pod_id, cluster_name, current_time, (void *)&combined);

    /* Hash the combined data using SHA256 */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)combined, strlen(combined), hash);

    /* XOR the hash with the additional entropy */
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        hash[i] ^= entropy[i];
    }

    /* Generate an additional 64-bit random number */
    uint64_t additional_random;
    if (RAND_bytes((unsigned char *)&additional_random, sizeof(additional_random)) != 1) {
        fprintf(stderr, "Error generating additional random bytes\n");
        return -1;
    }

    /* Initialize PCG random number generator */
    pcg32_random_t rng;
    rng.state = *(uint64_t *)hash ^ additional_random; /* XOR with additional random number */
    rng.inc = *(uint64_t *)(hash + 8);

    /* Generate random value and scale it to desired range */
    uint32_t random_value = pcg32_random_r(&rng);
    int random_integer = (random_value % 4200001) - 600000;

    return random_integer;
}


int azure_kusto_load_ingestion_resources(struct flb_azure_kusto *ctx,
                                         struct flb_config *config)
{
    int ret = -1;
    flb_sds_t response = NULL;
    flb_sds_t identity_token = NULL;
    struct flb_upstream_ha *blob_ha = NULL;
    struct flb_upstream_ha *queue_ha = NULL;
    struct flb_time tm_now;
    uint64_t now;

    int generated_random_integer = azure_kusto_generate_random_integer();
    flb_plg_debug(ctx->ins, "generated random integer %d", generated_random_integer);

    flb_time_get(&tm_now);
    now = flb_time_to_millisec(&tm_now);
    flb_plg_debug(ctx->ins, "current time %llu", now);
    flb_plg_debug(ctx->ins, "load_time is %llu", ctx->resources->load_time);
    flb_plg_debug(ctx->ins, "difference is  %llu", now - ctx->resources->load_time);
    flb_plg_debug(ctx->ins, "effective ingestion resource interval is %d", ctx->ingestion_resources_refresh_interval * 1000 + generated_random_integer);

    /* check if we have all resources and they are not stale */
    if (ctx->resources->blob_ha && ctx->resources->queue_ha &&
        ctx->resources->identity_token &&
        now - ctx->resources->load_time < ctx->ingestion_resources_refresh_interval * 1000 + generated_random_integer) {
        flb_plg_debug(ctx->ins, "resources are already loaded and are not stale");
        ret = 0;
    }
    else {
        flb_plg_info(ctx->ins, "loading kusto ingestion resources and refresh interval is %d", ctx->ingestion_resources_refresh_interval * 1000 + generated_random_integer);
        response = execute_ingest_csl_command(ctx, ".get ingestion resources");

        if (response) {
            queue_ha = flb_upstream_ha_create("azure_kusto_queue_ha");

            if (queue_ha) {
                blob_ha = flb_upstream_ha_create("azure_kusto_blob_ha");

                if (blob_ha) {

                    if (pthread_mutex_lock(&ctx->resources_mutex)) {
                        flb_plg_error(ctx->ins, "error locking mutex");
                        ret = -1;
                        goto cleanup;
                    }
                    ret =
                            parse_storage_resources(ctx, config, response, blob_ha, queue_ha);

                    if (pthread_mutex_unlock(&ctx->resources_mutex)) {
                        flb_plg_error(ctx->ins, "error unlocking mutex");
                        ret = -1;
                        goto cleanup;
                    }

                    if (ret == 0) {
                        flb_sds_destroy(response);
                        response = NULL;

                        response =
                                execute_ingest_csl_command(ctx, ".get kusto identity token");

                        if (response) {
                            if (pthread_mutex_lock(&ctx->resources_mutex)) {
                                flb_plg_error(ctx->ins, "error locking mutex");
                                ret = -1;
                                goto cleanup;
                            }
                            identity_token =
                                    parse_ingestion_identity_token(ctx, response);

                            if (identity_token) {
                                /* 
                                    Deferred cleanup: destroy resources from two refresh cycles ago,
                                    then move current resources to 'old' before assigning new ones.
                                    This avoids use-after-free when other threads may still be using
                                    the current resources during high-volume operations.
                                    
                                    With a 1-hour refresh interval, the race condition requires an 
                                    ingest operation to take >1 hour (the deferred cleanup grace period). 
                                    This is extremely unlikely under normal conditions (and hence a lock based 
                                    mechanism is avoided for performance).
                                */
                                if (ctx->resources->old_blob_ha) {
                                    flb_upstream_ha_destroy(ctx->resources->old_blob_ha);
                                    flb_plg_debug(ctx->ins, "clearing up old blob HA");
                                }
                                if (ctx->resources->old_queue_ha) {
                                    flb_upstream_ha_destroy(ctx->resources->old_queue_ha);
                                    flb_plg_debug(ctx->ins, "clearing up old queue HA");
                                }
                                if (ctx->resources->old_identity_token) {
                                    flb_sds_destroy(ctx->resources->old_identity_token);
                                    flb_plg_debug(ctx->ins, "clearing up old identity token");
                                }

                                /* Move current to old */
                                ctx->resources->old_blob_ha = ctx->resources->blob_ha;
                                ctx->resources->old_queue_ha = ctx->resources->queue_ha;
                                ctx->resources->old_identity_token = ctx->resources->identity_token;

                                /* Assign new resources */
                                ctx->resources->blob_ha = blob_ha;
                                ctx->resources->queue_ha = queue_ha;
                                ctx->resources->identity_token = identity_token;
                                ctx->resources->load_time = now;

                                flb_plg_info(ctx->ins, "ingestion resources rotated successfully, "
                                             "previous resources moved to deferred cleanup");

                                ret = 0;
                            }
                            else {
                                flb_plg_error(ctx->ins,
                                              "error parsing ingestion identity token");
                                ret = -1;
                                goto cleanup;
                            }
                            if (pthread_mutex_unlock(&ctx->resources_mutex)) {
                                flb_plg_error(ctx->ins, "error unlocking mutex");
                                ret = -1;
                                goto cleanup;
                            }
                        }
                        else {
                            flb_plg_error(ctx->ins, "error getting kusto identity token");
                            ret = -1;
                            goto cleanup;
                        }
                    }
                    else {
                        flb_plg_error(ctx->ins,
                                      "error parsing ingestion storage resources");
                        ret = -1;
                        goto cleanup;
                    }

                    if (ret == -1) {
                        flb_upstream_ha_destroy(blob_ha);
                        blob_ha = NULL;
                    }
                }
                else {
                    flb_plg_error(ctx->ins, "error creating storage resources upstreams");
                    ret = -1;
                    goto cleanup;
                }

                if (ret == -1) {
                    flb_upstream_ha_destroy(queue_ha);
                    queue_ha = NULL;
                }
            }
            else {
                flb_plg_error(ctx->ins, "error creating storage resources upstreams");
                ret = -1;
                goto cleanup;
            }

            if (response) {
                flb_sds_destroy(response);
            }
        }
        if (!response) {
            flb_plg_error(ctx->ins, "error getting ingestion storage resources");
            ret = -1;
            goto cleanup;
        }
    }

    cleanup:
    if (ret == -1) {
        if (queue_ha) {
            flb_upstream_ha_destroy(queue_ha);
        }
        if (blob_ha) {
            flb_upstream_ha_destroy(blob_ha);
        }
        if (response) {
            flb_sds_destroy(response);
        }
        if (identity_token) {
            flb_sds_destroy(identity_token);
        }
    }

    return ret;
}

static int flb_azure_kusto_resources_destroy(struct flb_azure_kusto_resources *resources)
{
    int ret;

    if (!resources) {
        return -1;
    }

    ret = flb_azure_kusto_resources_clear(resources);
    if (ret != 0) {
        return -1;
    }

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

    /* Auth method validation and setup */
    if (strcasecmp(ctx->auth_type_str, "service_principal") == 0) {
        ctx->auth_type = FLB_AZURE_KUSTO_AUTH_SERVICE_PRINCIPAL;
        
        /* Verify required parameters for Service Principal auth */
        if (!ctx->tenant_id || !ctx->client_id || !ctx->client_secret) {
            flb_plg_error(ins, "When using service_principal auth, tenant_id, client_id, and client_secret are required");
            flb_azure_kusto_conf_destroy(ctx);
            return NULL;
        }
    } 
    else if (strcasecmp(ctx->auth_type_str, "managed_identity") == 0) {
        /* Check if client_id indicates system-assigned or user-assigned managed identity */
        if (!ctx->client_id) {
            flb_plg_error(ins, "When using managed_identity auth, client_id must be set to 'system' for system-assigned or the managed identity client ID");
            flb_azure_kusto_conf_destroy(ctx);
            return NULL;
        }
        
        if (strcasecmp(ctx->client_id, "system") == 0) {
            ctx->auth_type = FLB_AZURE_KUSTO_AUTH_MANAGED_IDENTITY_SYSTEM;
        } else {
            ctx->auth_type = FLB_AZURE_KUSTO_AUTH_MANAGED_IDENTITY_USER;
        }
    }
    else if (strcasecmp(ctx->auth_type_str, "workload_identity") == 0) {
        ctx->auth_type = FLB_AZURE_KUSTO_AUTH_WORKLOAD_IDENTITY;
        
        /* Verify required parameters for Workload Identity auth */
        if (!ctx->tenant_id || !ctx->client_id) {
            flb_plg_error(ins, "When using workload_identity auth, tenant_id and client_id are required");
            flb_azure_kusto_conf_destroy(ctx);
            return NULL;
        }
        
        /* Set default token file path if not specified */
        if (!ctx->workload_identity_token_file) {
            ctx->workload_identity_token_file = flb_strdup("/var/run/secrets/azure/tokens/azure-identity-token");
            if (!ctx->workload_identity_token_file) {
                flb_errno();
                flb_plg_error(ins, "Could not allocate default workload identity token path");
                flb_azure_kusto_conf_destroy(ctx);
                return NULL;
            }
        }
    }
    else {
        flb_plg_error(ins, "Invalid auth_type '%s'. Valid options are: 'service_principal', 'managed_identity', or 'workload_identity'", 
                     ctx->auth_type_str);
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

    /* Create oauth2 context */
    if (ctx->auth_type == FLB_AZURE_KUSTO_AUTH_MANAGED_IDENTITY_SYSTEM || 
        ctx->auth_type == FLB_AZURE_KUSTO_AUTH_MANAGED_IDENTITY_USER) {
        /* MSI auth */
        /* Construct the URL template with or without client_id for managed identity */
        if (ctx->auth_type == FLB_AZURE_KUSTO_AUTH_MANAGED_IDENTITY_SYSTEM) {
            ctx->oauth_url = flb_sds_create_size(sizeof(FLB_AZURE_MSIAUTH_URL_TEMPLATE) - 1);
            if (!ctx->oauth_url) {
                flb_errno();
                flb_azure_kusto_conf_destroy(ctx);
                return NULL;
            }
            flb_sds_snprintf(&ctx->oauth_url, flb_sds_alloc(ctx->oauth_url),
                            FLB_AZURE_MSIAUTH_URL_TEMPLATE, "", "");
        } else {
            /* User-assigned managed identity */
            ctx->oauth_url = flb_sds_create_size(sizeof(FLB_AZURE_MSIAUTH_URL_TEMPLATE) - 1 +
                                                sizeof("&client_id=") - 1 +
                                                flb_sds_len(ctx->client_id));
            if (!ctx->oauth_url) {
                flb_errno();
                flb_azure_kusto_conf_destroy(ctx);
                return NULL;
            }
            flb_sds_snprintf(&ctx->oauth_url, flb_sds_alloc(ctx->oauth_url),
                            FLB_AZURE_MSIAUTH_URL_TEMPLATE, "&client_id=", ctx->client_id);
        }
    } else {
        /* Standard OAuth2 for service principal or workload identity */
        ctx->oauth_url = flb_sds_create_size(sizeof(FLB_MSAL_AUTH_URL_TEMPLATE) - 1 +
                                            flb_sds_len(ctx->tenant_id));
        if (!ctx->oauth_url) {
            flb_errno();
            flb_azure_kusto_conf_destroy(ctx);
            return NULL;
        }
        flb_sds_snprintf(&ctx->oauth_url, flb_sds_alloc(ctx->oauth_url),
                        FLB_MSAL_AUTH_URL_TEMPLATE, ctx->tenant_id);
    }

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

    flb_plg_info(ctx->ins, "before exiting the plugin kusto conf destroy called");

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
