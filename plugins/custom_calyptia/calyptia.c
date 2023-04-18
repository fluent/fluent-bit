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

#include <fluent-bit/flb_custom_plugin.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_router.h>

/* pipeline plugins */
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>

struct calyptia {
    /* config map options */
    flb_sds_t api_key;
    flb_sds_t store_path;
    flb_sds_t cloud_host;
    flb_sds_t cloud_port;
    flb_sds_t machine_id;
    flb_sds_t fleet_id;

/* used for reporting chunk trace records. */
#ifdef FLB_HAVE_CHUNK_TRACE
    flb_sds_t pipeline_id;
#endif /* FLB_HAVE_CHUNK_TRACE */

    int cloud_tls;
    int cloud_tls_verify;

    /* config reader for 'add_label' */
    struct mk_list *add_labels;

    /* instances */
    struct flb_input_instance *i;
    struct flb_output_instance *o;
    struct flb_custom_instance *ins;
};

/*
 * Check if the key belongs to a sensitive data field, if so report it. We never
 * share any sensitive data.
 */
static int is_sensitive_property(char *key)
{

    if (strcasecmp(key, "password") == 0 ||
        strcasecmp(key, "passwd") == 0   ||
        strcasecmp(key, "user") == 0 ||
        strcasecmp(key, "http_user") == 0 ||
        strcasecmp(key, "http_passwd") == 0 ||
        strcasecmp(key, "shared_key") == 0 ||
        strcasecmp(key, "endpoint") == 0 ||
        strcasecmp(key, "apikey") == 0 ||
        strcasecmp(key, "private_key") == 0 ||
        strcasecmp(key, "service_account_secret") == 0 ||
        strcasecmp(key, "splunk_token") == 0 ||
        strcasecmp(key, "logdna_host") == 0 ||
        strcasecmp(key, "api_key") == 0 ||
        strcasecmp(key, "hostname") == 0 ||
        strcasecmp(key, "license_key") == 0 ||
        strcasecmp(key, "base_uri") == 0 ||
        strcasecmp(key, "api") == 0) {

        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static void pipeline_config_add_properties(flb_sds_t *buf, struct mk_list *props)
{
    struct mk_list *head;
    struct flb_kv *kv;

    mk_list_foreach(head, props) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (kv->key != NULL && kv->val != NULL) {
            flb_sds_printf(buf, "    %s ", kv->key);

            if (is_sensitive_property(kv->key)) {
                flb_sds_cat_safe(buf, "--redacted--", strlen("--redacted--"));
            }
            else {
                flb_sds_cat_safe(buf, kv->val, strlen(kv->val));
            }

            flb_sds_cat_safe(buf, "\n", 1);
        }
    }
}

flb_sds_t custom_calyptia_pipeline_config_get(struct flb_config *ctx)
{
    char tmp[32];
    flb_sds_t buf;
    struct mk_list *head;
    struct flb_input_instance *i_ins;
    struct flb_filter_instance *f_ins;
    struct flb_output_instance *o_ins;

    buf = flb_sds_create_size(2048);
    if (!buf) {
        return NULL;
    }

    /* [INPUT] */
    mk_list_foreach(head, &ctx->inputs) {
        i_ins = mk_list_entry(head, struct flb_input_instance, _head);
        flb_sds_printf(&buf, "[INPUT]\n");
        flb_sds_printf(&buf, "    name %s\n", i_ins->name);
        if (i_ins->alias) {
            flb_sds_printf(&buf, "    alias %s\n", i_ins->alias);
        }
        if (i_ins->tag) {
            flb_sds_printf(&buf, "    tag %s\n", i_ins->tag);
        }

        if (i_ins->mem_buf_limit > 0) {
            flb_utils_bytes_to_human_readable_size(i_ins->mem_buf_limit,
                                                   tmp, sizeof(tmp) - 1);
            flb_sds_printf(&buf, "    mem_buf_limit %s\n", tmp);
        }

        pipeline_config_add_properties(&buf, &i_ins->properties);
    }
    flb_sds_printf(&buf, "\n");

    /* Config: [FILTER] */
    mk_list_foreach(head, &ctx->filters) {
        f_ins = mk_list_entry(head, struct flb_filter_instance, _head);
        flb_sds_printf(&buf, "[FILTER]\n");
        flb_sds_printf(&buf, "    name  %s\n", f_ins->name);
        flb_sds_printf(&buf, "    match %s\n", f_ins->match);

        pipeline_config_add_properties(&buf, &f_ins->properties);
    }
    flb_sds_printf(&buf, "\n");

    /* Config: [OUTPUT] */
    mk_list_foreach(head, &ctx->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);
        flb_sds_printf(&buf, "[OUTPUT]\n");
        flb_sds_printf(&buf, "    name  %s\n", o_ins->name);
        if (o_ins->match) {
            flb_sds_printf(&buf, "    match %s\n", o_ins->match);
        }
        else {
            flb_sds_printf(&buf, "    match *\n");
        }

#ifdef FLB_HAVE_TLS
        if (o_ins->use_tls == FLB_TRUE) {
            flb_sds_printf(&buf, "    tls   %s\n", o_ins->use_tls ? "on" : "off");
            flb_sds_printf(&buf, "    tls.verify     %s\n",
                             o_ins->tls_verify ? "on": "off");

            if (o_ins->tls_ca_file) {
                flb_sds_printf(&buf, "    tls.ca_file    %s\n",
                               o_ins->tls_ca_file);
            }

            if (o_ins->tls_crt_file) {
                flb_sds_printf(&buf, "    tls.crt_file   %s\n",
                               o_ins->tls_crt_file);
            }

            if (o_ins->tls_key_file) {
                flb_sds_printf(&buf, "    tls.key_file   %s\n",
                               o_ins->tls_key_file);
            }

            if (o_ins->tls_key_passwd) {
                flb_sds_printf(&buf, "    tls.key_passwd --redacted--\n");
            }
        }
#endif
        if (o_ins->retry_limit == FLB_OUT_RETRY_UNLIMITED) {
            flb_sds_printf(&buf, "    retry_limit no_limits\n");
        }
        else if (o_ins->retry_limit == FLB_OUT_RETRY_NONE) {
            flb_sds_printf(&buf, "    retry_limit no_retries\n");
        }
        else {
            flb_sds_printf(&buf, "    retry_limit %i\n", o_ins->retry_limit);
        }

        if (o_ins->host.name) {
            flb_sds_printf(&buf, "    host  --redacted--\n");
        }

        pipeline_config_add_properties(&buf, &o_ins->properties);
        flb_sds_printf(&buf, "\n");
    }

    return buf;
}

static int cb_calyptia_init(struct flb_custom_instance *ins,
                            struct flb_config *config,
                            void *data)
{
    int ret;
    struct calyptia *ctx;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *k = NULL;
    struct flb_slist_entry *v = NULL;
    (void) data;
    flb_sds_t kv;

    ctx = flb_calloc(1, sizeof(struct calyptia));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    /* Load the config map */
    ret = flb_custom_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* map instance and local context */
    flb_custom_set_context(ins, ctx);

    /* input collector */
    ctx->i = flb_input_new(config, "fluentbit_metrics", NULL, FLB_TRUE);
    if (!ctx->i) {
        flb_plg_error(ctx->ins, "could not load metrics collector");
        return -1;
    }
    flb_input_set_property(ctx->i, "tag", "_calyptia_cloud");
    flb_input_set_property(ctx->i, "scrape_on_start", "true");
    flb_input_set_property(ctx->i, "scrape_interval", "30");

    /* output cloud connector */
    ctx->o = flb_output_new(config, "calyptia", ctx, FLB_FALSE);
    if (!ctx->o) {
        flb_plg_error(ctx->ins, "could not load Calyptia Cloud connector");
        flb_free(ctx);
        return -1;
    }

    /* direct connect / routing */
    ret = flb_router_connect_direct(ctx->i, ctx->o);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not load Calyptia Cloud connector");
        flb_free(ctx);
        return -1;
    }

    if (ctx->add_labels && mk_list_size(ctx->add_labels) > 0) {
        /* iterate all 'add_label' definitions */
        flb_config_map_foreach(head, mv, ctx->add_labels) {
            k = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
            v = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);
            kv = flb_sds_create_size(strlen(k->str) + strlen(v->str) + 1);
            if(!kv) {
                flb_free(ctx);
                return -1;
            }

            flb_sds_printf(&kv, "%s %s", k->str, v->str);
            flb_output_set_property(ctx->o, "add_label", kv);
            flb_sds_destroy(kv);
        }
    }

    flb_output_set_property(ctx->o, "match", "_calyptia_cloud");
    flb_output_set_property(ctx->o, "api_key", ctx->api_key);
    if (ctx->store_path) {
        flb_output_set_property(ctx->o, "store_path", ctx->store_path);
    }

    if (ctx->machine_id) {
        flb_output_set_property(ctx->o, "machine_id", ctx->machine_id);
    }

    if (ctx->fleet_id) {
        flb_output_set_property(ctx->o, "fleet_id", ctx->fleet_id);
    }

    /* Override network details: development purposes only */
    if (ctx->cloud_host) {
        flb_output_set_property(ctx->o, "cloud_host", ctx->cloud_host);
    }

    if (ctx->cloud_port) {
        flb_output_set_property(ctx->o, "cloud_port", ctx->cloud_port);
    }

    if (ctx->cloud_tls) {
        flb_output_set_property(ctx->o, "tls", "true");
    }
    else {
        flb_output_set_property(ctx->o, "tls", "false");
    }

    if (ctx->cloud_tls_verify) {
        flb_output_set_property(ctx->o, "tls.verify", "true");
    }
    else {
        flb_output_set_property(ctx->o, "tls.verify", "false");
    }

#ifdef FLB_HAVE_CHUNK_TRACE
    flb_output_set_property(ctx->o, "pipeline_id", ctx->pipeline_id);
#endif /* FLB_HAVE_CHUNK_TRACE */

    flb_router_connect(ctx->i, ctx->o);
    flb_plg_info(ins, "custom initialized!");
    return 0;
}

static int cb_calyptia_exit(void *data, struct flb_config *config)
{
    struct calyptia *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "api_key", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, api_key),
     "Calyptia Cloud API Key."
    },

    {
     FLB_CONFIG_MAP_STR, "store_path", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, store_path)
    },

    {
     FLB_CONFIG_MAP_STR, "calyptia_host", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, cloud_host),
     ""
    },

    {
     FLB_CONFIG_MAP_STR, "calyptia_port", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, cloud_port),
     ""
    },

    {
     FLB_CONFIG_MAP_BOOL, "calyptia_tls", "true",
     0, FLB_TRUE, offsetof(struct calyptia, cloud_tls),
     ""
    },

    {
     FLB_CONFIG_MAP_BOOL, "calyptia_tls.verify", "true",
     0, FLB_TRUE, offsetof(struct calyptia, cloud_tls_verify),
     ""
    },

    {
     FLB_CONFIG_MAP_SLIST_1, "add_label", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct calyptia, add_labels),
     "Label to append to the generated metric."
    },
    {
     FLB_CONFIG_MAP_STR, "machine_id", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, machine_id),
     "Custom machine_id to be used when registering agent"
    },
    {
     FLB_CONFIG_MAP_STR, "fleet_id", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, fleet_id),
     "Fleet id to be used when registering agent in a fleet"
    },

#ifdef FLB_HAVE_CHUNK_TRACE
    {
     FLB_CONFIG_MAP_STR, "pipeline_id", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, pipeline_id),
     "Pipeline ID for reporting to calyptia cloud."
    },
#endif /* FLB_HAVE_CHUNK_TRACE */

    /* EOF */
    {0}
};

struct flb_custom_plugin custom_calyptia_plugin = {
    .name         = "calyptia",
    .description  = "Calyptia Cloud",
    .config_map   = config_map,
    .cb_init      = cb_calyptia_init,
    .cb_exit      = cb_calyptia_exit,
};
