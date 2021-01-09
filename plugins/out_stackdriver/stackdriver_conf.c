/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <jsmn/jsmn.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "stackdriver.h"
#include "stackdriver_conf.h"

static inline int key_cmp(const char *str, int len, const char *cmp) {

    if (strlen(cmp) != len) {
        return -1;
    }

    return strncasecmp(str, cmp, len);
}

static int read_credentials_file(const char *creds, struct flb_stackdriver *ctx)
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
    ret = stat(creds, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open credentials file: %s",
                      creds);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "credentials file "
                      "is not a valid file: %s", creds);
        return -1;
    }

    /* Read file content */
    buf = mk_file_to_buffer(creds);
    if (!buf) {
        flb_plg_error(ctx->ins, "error reading credentials file: %s",
                      creds);
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
                  creds);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    t = &tokens[0];
    if (t->type != JSMN_OBJECT) {
        flb_plg_error(ctx->ins, "invalid JSON map on file: %s",
                  creds);
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
            ctx->type = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "project_id") == 0) {
            ctx->project_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "private_key_id") == 0) {
            ctx->private_key_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "private_key") == 0) {
            tmp = flb_sds_create_len(val, val_len);
            if (tmp) {
                /* Unescape private key */
                ctx->private_key = flb_sds_create_size(val_len);
                flb_unescape_string(tmp, flb_sds_len(tmp),
                                    &ctx->private_key);
                flb_sds_destroy(tmp);
            }
        }
        else if (key_cmp(key, key_len, "client_email") == 0) {
            ctx->client_email = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "client_id") == 0) {
            ctx->client_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "auth_uri") == 0) {
            ctx->auth_uri = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "token_uri") == 0) {
            ctx->token_uri = flb_sds_create_len(val, val_len);
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
    struct flb_stackdriver *ctx;

    /* Allocate config context */
    ctx = flb_calloc(1, sizeof(struct flb_stackdriver));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->config = config;

    /* Lookup credentials file */
    tmp = flb_output_get_property("google_service_credentials", ins);
    if (tmp) {
        ctx->credentials_file = flb_sds_create(tmp);
    }
    else {
        tmp = getenv("GOOGLE_SERVICE_CREDENTIALS");
        if (tmp) {
            ctx->credentials_file = flb_sds_create(tmp);
        }
    }

    if (ctx->credentials_file) {
        ret = read_credentials_file(ctx->credentials_file, ctx);
        if (ret != 0) {
            flb_stackdriver_conf_destroy(ctx);
            return NULL;
        }
    }
    else {
        /*
         * If no credentials file has been defined, do manual lookup of the
         * client email and the private key
         */

        /* Service Account Email */
        tmp = flb_output_get_property("service_account_email", ins);
        if (tmp) {
            ctx->client_email = flb_sds_create(tmp);
        }
        else {
            tmp = getenv("SERVICE_ACCOUNT_EMAIL");
            if (tmp) {
                ctx->client_email = flb_sds_create(tmp);
            }
        }

        /* Service Account Secret */
        tmp = flb_output_get_property("service_account_secret", ins);
        if (tmp) {
            ctx->private_key = flb_sds_create(tmp);
        }
        else {
            tmp = getenv("SERVICE_ACCOUNT_SECRET");
            if (tmp) {
                ctx->private_key = flb_sds_create(tmp);
            }
        }
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
        ctx->client_email = flb_sds_create("default");
    }
    if (!ctx->private_key) {
        flb_plg_warn(ctx->ins, "private_key is not defined, fetching "
                     "it from metadata server");
        ctx->metadata_server_auth = true;
    }

    tmp = flb_output_get_property("resource", ins);
    if (tmp) {
        ctx->resource = flb_sds_create(tmp);
    }
    else {
        ctx->resource = flb_sds_create(FLB_SDS_RESOURCE_TYPE);
    }

    tmp = flb_output_get_property("severity_key", ins);
    if (tmp) {
        ctx->severity_key = flb_sds_create(tmp);
    }
    else {
        ctx->severity_key = flb_sds_create(DEFAULT_SEVERITY_KEY);
    }

    tmp = flb_output_get_property("autoformat_stackdriver_trace", ins);
    if (tmp) {
        ctx->autoformat_stackdriver_trace = flb_utils_bool(tmp);
    }
    else {
        ctx->autoformat_stackdriver_trace = FLB_FALSE;
    }

    tmp = flb_output_get_property("trace_key", ins);
    if (tmp) {
        ctx->trace_key = flb_sds_create(tmp);
    }
    else {
        ctx->trace_key = flb_sds_create(DEFAULT_TRACE_KEY);
    }

    tmp = flb_output_get_property("log_name_key", ins);
    if (tmp) {
        ctx->log_name_key = flb_sds_create(tmp);
    }
    else {
        ctx->log_name_key = flb_sds_create(DEFAULT_LOG_NAME_KEY);
    }

    if (flb_sds_cmp(ctx->resource, "k8s_container",
                    flb_sds_len(ctx->resource)) == 0 ||
        flb_sds_cmp(ctx->resource, "k8s_node",
                    flb_sds_len(ctx->resource)) == 0 ||
        flb_sds_cmp(ctx->resource, "k8s_pod",
                    flb_sds_len(ctx->resource)) == 0) {

        ctx->k8s_resource_type = FLB_TRUE;

        tmp = flb_output_get_property("k8s_cluster_name", ins);
        if (tmp) {
            ctx->cluster_name = flb_sds_create(tmp);
        }

        tmp = flb_output_get_property("k8s_cluster_location", ins);
        if (tmp) {
            ctx->cluster_location = flb_sds_create(tmp);
        }

        if (!ctx->cluster_name || !ctx->cluster_location) {
            flb_plg_error(ctx->ins, "missing k8s_cluster_name "
                          "or k8s_cluster_location in configuration");
            flb_stackdriver_conf_destroy(ctx);
            return NULL;
        }
    }

    tmp = flb_output_get_property("labels_key", ins);
    if (tmp) {
        ctx->labels_key = flb_sds_create(tmp);
    }
    else {
        ctx->labels_key = flb_sds_create(DEFAULT_LABELS_KEY);
    }

    tmp = flb_output_get_property("tag_prefix", ins);
    if (tmp) {
        ctx->tag_prefix = flb_sds_create(tmp);
    }
    else {
        if (ctx->k8s_resource_type == FLB_TRUE) {
            ctx->tag_prefix = flb_sds_create(ctx->resource);
        }
    }

    return ctx;
}

int flb_stackdriver_conf_destroy(struct flb_stackdriver *ctx)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->k8s_resource_type){
        flb_sds_destroy(ctx->namespace_name);
        flb_sds_destroy(ctx->pod_name);
        flb_sds_destroy(ctx->container_name);
        flb_sds_destroy(ctx->node_name);
        flb_sds_destroy(ctx->cluster_name);
        flb_sds_destroy(ctx->cluster_location);
        flb_sds_destroy(ctx->local_resource_id);
    }

    flb_sds_destroy(ctx->credentials_file);
    flb_sds_destroy(ctx->type);
    flb_sds_destroy(ctx->project_id);
    flb_sds_destroy(ctx->private_key_id);
    flb_sds_destroy(ctx->private_key);
    flb_sds_destroy(ctx->client_email);
    flb_sds_destroy(ctx->client_id);
    flb_sds_destroy(ctx->auth_uri);
    flb_sds_destroy(ctx->token_uri);
    flb_sds_destroy(ctx->resource);
    flb_sds_destroy(ctx->severity_key);
    flb_sds_destroy(ctx->trace_key);
    flb_sds_destroy(ctx->log_name_key);
    flb_sds_destroy(ctx->labels_key);
    flb_sds_destroy(ctx->tag_prefix);

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

    flb_free(ctx);

    return 0;
}
