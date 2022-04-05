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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_sds.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "gce_metadata.h"
#include "stackdriver.h"
#include "stackdriver_conf.h"

static inline int key_cmp(const char *str, int len, const char *cmp) {

    if (strlen(cmp) != len) {
        return -1;
    }

    return strncasecmp(str, cmp, len);
}

static int read_credentials_file(const char *cred_file, struct flb_stackdriver *ctx)
{
    int i;
    int ret;
    int key_len;
    int val_len;
    int tok_size = 32;
    char *buf;
    char *key;
    char *val;
    flb_sds_t tmp;
    struct stat st;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;

    /* Validate credentials path */
    ret = stat(cred_file, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open credentials file: %s",
                      cred_file);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "credentials file "
                      "is not a valid file: %s", cred_file);
        return -1;
    }

    /* Read file content */
    buf = mk_file_to_buffer(cred_file);
    if (!buf) {
        flb_plg_error(ctx->ins, "error reading credentials file: %s",
                      cred_file);
        return -1;
    }

    /* Parse content */
    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_errno();
        flb_free(buf);
        return -1;
    }

    ret = jsmn_parse(&parser, buf, st.st_size, tokens, tok_size);
    if (ret <= 0) {
        flb_plg_error(ctx->ins, "invalid JSON credentials file: %s",
                  cred_file);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    t = &tokens[0];
    if (t->type != JSMN_OBJECT) {
        flb_plg_error(ctx->ins, "invalid JSON map on file: %s",
                  cred_file);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    /* Parse JSON tokens */
    for (i = 1; i < ret; i++) {
        t = &tokens[i];
        if (t->type != JSMN_STRING) {
            continue;
        }

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)){
            break;
        }

        /* Key */
        key = buf + t->start;
        key_len = (t->end - t->start);

        /* Value */
        i++;
        t = &tokens[i];
        val = buf + t->start;
        val_len = (t->end - t->start);

        if (key_cmp(key, key_len, "type") == 0) {
            ctx->creds->type = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "project_id") == 0) {
            ctx->project_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "private_key_id") == 0) {
            ctx->creds->private_key_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "private_key") == 0) {
            tmp = flb_sds_create_len(val, val_len);
            if (tmp) {
                /* Unescape private key */
                ctx->creds->private_key = flb_sds_create_size(val_len);
                flb_unescape_string(tmp, flb_sds_len(tmp),
                                    &ctx->creds->private_key);
                flb_sds_destroy(tmp);
            }
        }
        else if (key_cmp(key, key_len, "client_email") == 0) {
            ctx->creds->client_email = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "client_id") == 0) {
            ctx->creds->client_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "auth_uri") == 0) {
            ctx->creds->auth_uri = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "token_uri") == 0) {
            ctx->creds->token_uri = flb_sds_create_len(val, val_len);
        }
    }

    flb_free(buf);
    flb_free(tokens);

    return 0;
}

struct flb_stackdriver *flb_stackdriver_conf_create(struct flb_output_instance *ins,
                                                    struct flb_config *config)
{
    int ret;
    const char *tmp;
    const char *backwards_compatible_env_var;
    struct flb_stackdriver *ctx;
    size_t http_request_key_size;

    /* Allocate config context */
    ctx = flb_calloc(1, sizeof(struct flb_stackdriver));
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

    /* Lookup metadata server URL */
    if (ctx->metadata_server == NULL) {
        tmp = getenv("METADATA_SERVER");
        if(tmp) {
            if (ctx->env == NULL) {
                ctx->env = flb_calloc(1, sizeof(struct flb_stackdriver_env));
                if (ctx->env == NULL) {
                    flb_plg_error(ins, "unable to allocate env variables");
                    flb_free(ctx);
                    return NULL;
                }
            }
            ctx->env->metadata_server = flb_sds_create(tmp);
            ctx->metadata_server = ctx->env->metadata_server;
        }
    }
    flb_plg_info(ctx->ins, "metadata_server set to %s", ctx->metadata_server);

    /* Lookup credentials file */
    if (ctx->credentials_file == NULL) {
        /*
         * Use GOOGLE_APPLICATION_CREDENTIALS to fetch the credentials.
         * GOOGLE_SERVICE_CREDENTIALS is checked for backwards compatibility.
         */
        tmp = getenv("GOOGLE_APPLICATION_CREDENTIALS");
        backwards_compatible_env_var = getenv("GOOGLE_SERVICE_CREDENTIALS");
        if (tmp && backwards_compatible_env_var) {
            flb_plg_warn(ctx->ins, "GOOGLE_APPLICATION_CREDENTIALS and "
                "GOOGLE_SERVICE_CREDENTIALS are both defined. "
                "Defaulting to GOOGLE_APPLICATION_CREDENTIALS");
        }
        if ((tmp || backwards_compatible_env_var) && (ctx->env == NULL)) {
            ctx->env = flb_calloc(1, sizeof(struct flb_stackdriver_env));
            if (ctx->env == NULL) {
                flb_plg_error(ins, "unable to allocate env variables");
                flb_free(ctx);
                return NULL;
            }
        }
        if (tmp) {
            ctx->env->creds_file = flb_sds_create(tmp);
            ctx->credentials_file = ctx->env->creds_file;
        }
        else if (backwards_compatible_env_var) {
            ctx->env->creds_file = flb_sds_create(backwards_compatible_env_var);
            ctx->credentials_file = ctx->env->creds_file;
        }
    }

    if (ctx->credentials_file) {
        ctx->creds = flb_calloc(1, sizeof(struct flb_stackdriver_oauth_credentials));
        if (ctx->creds == NULL) {
            flb_plg_error(ctx->ins, "unable to allocate credentials");
            flb_stackdriver_conf_destroy(ctx);
            return NULL;
        }
        ret = read_credentials_file(ctx->credentials_file, ctx);
        if (ret != 0) {
            flb_stackdriver_conf_destroy(ctx);
            return NULL;
        }
        ctx->type = ctx->creds->type;
        ctx->private_key_id = ctx->creds->private_key_id;
        ctx->private_key = ctx->creds->private_key;
        ctx->client_email = ctx->creds->client_email;
        ctx->client_id = ctx->creds->client_id;
        ctx->auth_uri = ctx->creds->auth_uri;
        ctx->token_uri = ctx->creds->token_uri;
    }
    else {
        /*
         * If no credentials file has been defined, do manual lookup of the
         * client email and the private key
         */
        ctx->creds = flb_calloc(1, sizeof(struct flb_stackdriver_oauth_credentials));
        if (ctx->creds == NULL) {
            flb_plg_error(ctx->ins, "unable to allocate credentials");
            flb_stackdriver_conf_destroy(ctx);
            return NULL;
        }
        
        /* Service Account Email */
        if (ctx->client_email == NULL) {
            tmp = getenv("SERVICE_ACCOUNT_EMAIL");
            if (tmp) {
                ctx->creds->client_email = flb_sds_create(tmp);
            }
        }

        /* Service Account Secret */
        if (ctx->private_key == NULL) {
            tmp = getenv("SERVICE_ACCOUNT_SECRET");
            if (tmp) {
                ctx->creds->private_key = flb_sds_create(tmp);
            }
        }

        ctx->private_key = ctx->creds->private_key;
        ctx->client_email = ctx->creds->client_email;
    }

    /*
     * If only client email has been provided, fetch token from
     * the GCE metadata server.
     *
     * If no credentials have been provided, fetch token from the GCE
     * metadata server for default account.
     */
    if (!ctx->client_email && ctx->private_key) {
        flb_plg_error(ctx->ins, "client_email is not defined");
        flb_stackdriver_conf_destroy(ctx);
        return NULL;
    }

    if (!ctx->client_email) {
        flb_plg_warn(ctx->ins, "client_email is not defined, using "
                     "a default one");
        if (ctx->creds == NULL) {
            ctx->creds = flb_calloc(1, sizeof(struct flb_stackdriver_oauth_credentials));
            if (ctx->creds == NULL) {
                flb_plg_error(ctx->ins, "unable to allocate credentials");
                flb_stackdriver_conf_destroy(ctx);
                return NULL;
            }
        }
        ctx->creds->client_email = flb_sds_create("default");
        ctx->client_email = ctx->creds->client_email;
    }
    if (!ctx->private_key) {
        flb_plg_warn(ctx->ins, "private_key is not defined, fetching "
                     "it from metadata server");
        ctx->metadata_server_auth = true;
    }

    if (ctx->http_request_key) {
        http_request_key_size = flb_sds_len(ctx->http_request_key);
        if (http_request_key_size >= INT_MAX) {
            flb_plg_error(ctx->ins, "http_request_key is too long");
            flb_sds_destroy(ctx->http_request_key);
            ctx->http_request_key = NULL;
            ctx->http_request_key_size = 0;
        } else {
            ctx->http_request_key_size = http_request_key_size;
        }
    }

    if (flb_sds_cmp(ctx->resource, "k8s_container",
                    flb_sds_len(ctx->resource)) == 0 ||
        flb_sds_cmp(ctx->resource, "k8s_node",
                    flb_sds_len(ctx->resource)) == 0 ||
        flb_sds_cmp(ctx->resource, "k8s_pod",
                    flb_sds_len(ctx->resource)) == 0) {

        ctx->is_k8s_resource_type = FLB_TRUE;

        if (!ctx->cluster_name || !ctx->cluster_location) {
            flb_plg_error(ctx->ins, "missing k8s_cluster_name "
                          "or k8s_cluster_location in configuration");
            flb_stackdriver_conf_destroy(ctx);
            return NULL;
        }
    }

    if (flb_sds_cmp(ctx->resource, "generic_node",
                    flb_sds_len(ctx->resource)) == 0 ||
        flb_sds_cmp(ctx->resource, "generic_task",
                    flb_sds_len(ctx->resource)) == 0) {

        ctx->is_generic_resource_type = FLB_TRUE;

        if (ctx->location == NULL) {
            flb_plg_error(ctx->ins, "missing generic resource's location");
        }

        if (ctx->namespace_id == NULL) {
            flb_plg_error(ctx->ins, "missing generic resource's namespace");
        }

        if (flb_sds_cmp(ctx->resource, "generic_node",
                    flb_sds_len(ctx->resource)) == 0) {
            if (ctx->node_id == NULL) {
                flb_plg_error(ctx->ins, "missing generic_node's node_id");
                flb_stackdriver_conf_destroy(ctx);
                return NULL;
            }
        }
        else {
            if (ctx->job == NULL) {
                flb_plg_error(ctx->ins, "missing generic_task's job");
            }

            if (ctx->task_id == NULL) {
                flb_plg_error(ctx->ins, "missing generic_task's task_id");
            }

            if (!ctx->job || !ctx->task_id) {
                flb_stackdriver_conf_destroy(ctx);
                return NULL;
            }
        }

        if (!ctx->location || !ctx->namespace_id) {
            flb_stackdriver_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->tag_prefix == NULL && ctx->is_k8s_resource_type == FLB_TRUE) {
        /* allocate the flb_sds_t to tag_prefix_k8s so we can safely deallocate it */
        ctx->tag_prefix_k8s = flb_sds_create(ctx->resource);
        ctx->tag_prefix_k8s = flb_sds_cat(ctx->tag_prefix_k8s, ".", 1);
        ctx->tag_prefix = ctx->tag_prefix_k8s;
    }

    /* Register metrics */
#ifdef FLB_HAVE_METRICS
    ctx->cmt_successful_requests = cmt_counter_create(ins->cmt,
                                                      "fluentbit",
                                                      "stackdriver",
                                                      "successful_requests",
                                                      "Total number of successful "
                                                      "requests.",
                                                      1, (char *[]) {"name"});

    ctx->cmt_failed_requests = cmt_counter_create(ins->cmt,
                                                  "fluentbit",
                                                  "stackdriver",
                                                  "failed_requests",
                                                  "Total number of failed "
                                                  "requests.",
                                                  1, (char *[]) {"name"});

    ctx->cmt_requests_total = cmt_counter_create(ins->cmt,
                                                 "fluentbit",
                                                 "stackdriver",
                                                 "requests_total",
                                                 "Total number of requests.",
                                                  1, (char *[]) {"status"});

    ctx->cmt_proc_records_total = cmt_counter_create(ins->cmt,
                                                     "fluentbit",
                                                     "stackdriver",
                                                     "proc_records_total",
                                                     "Total number of processed records.",
                                                     1, (char *[]) {"status"});

    ctx->cmt_retried_records_total = cmt_counter_create(ins->cmt,
                                                        "fluentbit",
                                                        "stackdriver",
                                                        "retried_records_total",
                                                        "Total number of retried records.",
                                                        1, (char *[]) {"status"});

    /* OLD api */
    flb_metrics_add(FLB_STACKDRIVER_SUCCESSFUL_REQUESTS,
                    "stackdriver_successful_requests", ctx->ins->metrics);
    flb_metrics_add(FLB_STACKDRIVER_FAILED_REQUESTS,
                    "stackdriver_failed_requests", ctx->ins->metrics);
#endif

    return ctx;
}

int flb_stackdriver_conf_destroy(struct flb_stackdriver *ctx)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->creds) {
        if (ctx->creds->type) {
            flb_sds_destroy(ctx->creds->type);
        }
        if (ctx->creds->private_key_id) {
            flb_sds_destroy(ctx->creds->private_key_id);
        }
        if (ctx->creds->private_key) {
            flb_sds_destroy(ctx->creds->private_key);
        }
        if (ctx->creds->client_email) {
            flb_sds_destroy(ctx->creds->client_email);
        }
        if (ctx->creds->client_id) {
            flb_sds_destroy(ctx->creds->client_id);
        }
        if (ctx->creds->auth_uri) {
            flb_sds_destroy(ctx->creds->auth_uri);
        }
        if (ctx->creds->token_uri) {
            flb_sds_destroy(ctx->creds->token_uri);
        }
        flb_free(ctx->creds);
    }
    
    if (ctx->env) {
        if (ctx->env->creds_file) {
            flb_sds_destroy(ctx->env->creds_file);
        }
        if (ctx->env->metadata_server) {
            flb_sds_destroy(ctx->env->metadata_server);
        }
        flb_free(ctx->env);
    }
    
    if (ctx->is_k8s_resource_type){
        flb_sds_destroy(ctx->namespace_name);
        flb_sds_destroy(ctx->pod_name);
        flb_sds_destroy(ctx->container_name);
        flb_sds_destroy(ctx->node_name);
        flb_sds_destroy(ctx->local_resource_id);
    }
    
    if (ctx->metadata_server_auth) {
        flb_sds_destroy(ctx->zone);
        flb_sds_destroy(ctx->instance_id);
    }

    if (ctx->metadata_u) {
        flb_upstream_destroy(ctx->metadata_u);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->o) {
        flb_oauth2_destroy(ctx->o);
    }

    if (ctx->regex) {
        flb_regex_destroy(ctx->regex);
    }
    
    if (ctx->project_id) {
        flb_sds_destroy(ctx->project_id);
    }
    
    if (ctx->tag_prefix_k8s) {
        flb_sds_destroy(ctx->tag_prefix_k8s);
    }

    flb_free(ctx);

    return 0;
}
