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
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_unescape.h>

#include <jsmn/jsmn.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "stackdriver.h"
#include "stackdriver_conf.h"

/*
 * The valid Stackdriver monitored resources Fluent Bit can process.
 *
 * This also contains the valid labels for those resources, and
 * a way to store the value to those labels.
 *
 * For more info see: https://cloud.google.com/logging/docs/api/v2/resource-list
 * Any resource labels not specified here will be dropped.
 */
struct flb_std_resource valid_resources[] = {
    {"global", {
        {"project_id", NULL},
        {NULL}
    }, true},
    {"gce_instance", {
        {"project_id", NULL},
        {"zone", NULL},
        {"instance_id", NULL},
        {NULL},
    }, true},
    {"generic_node", {
        {"project_id", NULL},
        {"location", NULL},
        {"namespace", NULL},
        {"node_id", NULL},
        {NULL}
    }, false},
    {"generic_task", {
        {"project_id", NULL},
        {"location", NULL},
        {"namespace", NULL},
        {"job", NULL},
        {"task_id", NULL},
        {NULL}
    }, false},
    {NULL},
};

static inline int key_cmp(const char *str, int len, const char *cmp) {

    if (strlen(cmp) != len) {
        return -1;
    }

    return strncasecmp(str, cmp, len);
}

static int validate_resource(const char *res, struct flb_stackdriver *ctx)
{
    int i = 0;
    if (res == NULL) {
        flb_plg_debug(ctx->ins, "Setting resource as global");
        ctx->resource = &valid_resources[0];
        return 0;
    }
    while(valid_resources[i].type != NULL) {
        if (strncmp(valid_resources[i].type, res, strlen(res)) == 0) {
            flb_plg_debug(ctx->ins,
                "Setting resource as %s", valid_resources[i].type);
            ctx->resource = &valid_resources[i];
            return 0;
        }
        ++i;
    }
    return -1;
}

int set_resource_label(const char *key, const char *val, struct flb_stackdriver *ctx)
{
    int i = 0;
    while (ctx->resource->labels[i].label != NULL) {
        if (strncmp(ctx->resource->labels[i].label, key, strlen(key)) == 0) {
            flb_plg_debug(ctx->ins,
                "Setting label %s: %s", ctx->resource->labels[i].label, val);
            ctx->resource->labels[i].value = flb_sds_create(val);
            return 0;
        }
        ++i;
    }
    return -1;
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
    bool seen_project_id;
    int i;
    int ret;
    const char *tmp;
    flb_sds_t key;
    static const char rlabel_prefix[] = "resource_label.";
    struct flb_stackdriver *ctx;
    // struct flb_kv *kv;
    // struct mk_list *label;


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

    /* set metadata server url with default, then replace if spec'd in config */
    ctx->metadata_server = flb_sds_create(FLB_STD_META_URL);
    tmp = flb_output_get_property("metadata_server", ins);
    if (tmp) {
        ctx->metadata_server = flb_sds_create(tmp);
    }

    tmp = flb_output_get_property("resource", ins);
    if (validate_resource(tmp, ctx) != 0) {
        flb_plg_error(ctx->ins, "unsupported resource type '%s'", tmp);
        flb_stackdriver_conf_destroy(ctx);
        return NULL;
    }

    /*
     * Load monitored resource labels from config files.
     *  Labels that don't match for a particular resource type will be
     *  dropped since they will silently be rejected by the API anyway.
     */
    seen_project_id = false;
    i = 0;
    while(ctx->resource->labels[i].label != NULL) {
        key = flb_sds_create(rlabel_prefix);
        key = flb_sds_cat(key, ctx->resource->labels[i].label, strlen(ctx->resource->labels[i].label));
        flb_plg_debug(ctx->ins, "key = %s", key);
        tmp = flb_output_get_property(key, ins);
        if (tmp) {
            ctx->resource->labels[i].value = flb_sds_create(tmp);
            flb_plg_debug(ctx->ins,
                "Added label %s: %s", ctx->resource->labels[i].label, tmp);
        }
        flb_sds_destroy(key);
        ++i;
    }

    /*
    * Sets project_id label if it was not overridden in the conf file.
    * If it was not set in the conf file or credential file it will be
    * retrieved from the gce metadata server later.
    */
    if (!seen_project_id && ctx->project_id) {
        set_resource_label("project_id", ctx->project_id, ctx);
        flb_plg_debug(ctx->ins,
            "Added label %s: %s", "project_id", ctx->project_id);
    }

    tmp = flb_output_get_property("severity_key", ins);
    if (tmp) {
        ctx->severity_key = flb_sds_create(tmp);
    }

    return ctx;
}

int flb_stackdriver_conf_destroy(struct flb_stackdriver *ctx)
{
    int i = 0;
    if (!ctx) {
        return -1;
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
    flb_sds_destroy(ctx->severity_key);

    while (ctx->resource->labels[i].label != NULL) {
        flb_sds_destroy(ctx->resource->labels[i].value);
        ++i;
    }

    if (ctx->o) {
        flb_oauth2_destroy(ctx->o);
    }

    flb_sds_destroy(ctx->metadata_server);

    if (ctx->metadata_u) {
        flb_upstream_destroy(ctx->metadata_u);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }
    flb_free(ctx);

    return 0;
}
