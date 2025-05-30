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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_custom.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_plugin_proxy.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_downstream.h>
#include <chunkio/chunkio.h>

static inline int instance_id(struct flb_config *config)
{
    struct flb_custom_instance *entry;

    if (mk_list_size(&config->customs) == 0) {
        return 0;
    }

    entry = mk_list_entry_last(&config->customs, struct flb_custom_instance,
                               _head);
    return (entry->id + 1);
}

static inline int prop_key_check(const char *key, const char *kv, int k_len)
{
    int len;

    len = strlen(key);
    if (strncasecmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }

    return -1;
}

int flb_custom_set_property(struct flb_custom_instance *ins,
                            const char *k, const char *v)
{
    int len;
    int ret;
    flb_sds_t tmp;
    struct flb_kv *kv;

    len = strlen(k);
    tmp = flb_env_var_translate(ins->config->env, v);
    if (!tmp) {
        return -1;
    }

    if (prop_key_check("alias", k, len) == 0 && tmp) {
        flb_utils_set_plugin_string_property("alias", &ins->alias, tmp);
    }
    else if (prop_key_check("log_level", k, len) == 0 && tmp) {
        ret = flb_log_get_level_str(tmp);
        flb_sds_destroy(tmp);
        if (ret == -1) {
            return -1;
        }
        ins->log_level = ret;
    }
    else if (strncasecmp("net.", k, 4) == 0 && tmp) {
        kv = flb_kv_item_create(&ins->net_properties, (char *) k, NULL);
        if (!kv) {
            if (tmp) {
                flb_sds_destroy(tmp);
            }
            return -1;
        }
        kv->val = tmp;
    }
    else {
        /*
         * Create the property, we don't pass the value since we will
         * map it directly to avoid an extra memory allocation.
         */
        kv = flb_kv_item_create(&ins->properties, (char *) k, NULL);
        if (!kv) {
            if (tmp) {
                flb_sds_destroy(tmp);
            }
            return -1;
        }
        kv->val = tmp;
    }

    return 0;
}

const char *flb_custom_get_property(const char *key,
                                    struct flb_custom_instance *ins)
{
    return flb_kv_get_key_value(key, &ins->properties);
}

void flb_custom_instance_exit(struct flb_custom_instance *ins,
                              struct flb_config *config)
{
    struct flb_custom_plugin *p;

    p = ins->p;
    if (p->cb_exit && ins->context) {
        p->cb_exit(ins->context, config);
    }
}

/* Invoke exit call for the custom plugin */
void flb_custom_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_custom_instance *ins;
    struct flb_custom_plugin *p;

    mk_list_foreach_safe(head, tmp, &config->customs) {
        ins = mk_list_entry(head, struct flb_custom_instance, _head);
        p = ins->p;
        if (!p) {
            continue;
        }
        flb_custom_instance_exit(ins, config);
        flb_custom_instance_destroy(ins);
    }
}

struct flb_custom_instance *flb_custom_new(struct flb_config *config,
                                           const char *custom, void *data)
{
    int id;
    struct mk_list *head;
    struct flb_custom_plugin *plugin;
    struct flb_custom_instance *instance = NULL;
    struct flb_plugin_proxy_context *ctx;

    if (!custom) {
        return NULL;
    }

    mk_list_foreach(head, &config->custom_plugins) {
        plugin = mk_list_entry(head, struct flb_custom_plugin, _head);
        if (strcmp(plugin->name, custom) == 0) {
            break;
        }
        plugin = NULL;
    }

    if (!plugin) {
        return NULL;
    }

    instance = flb_calloc(1, sizeof(struct flb_custom_instance));
    if (!instance) {
        flb_errno();
        return NULL;
    }
    instance->config = config;

    /* Get an ID */
    id =  instance_id(config);

    /* format name (with instance id) */
    snprintf(instance->name, sizeof(instance->name) - 1,
             "%s.%i", plugin->name, id);

    if (plugin->type == FLB_CUSTOM_PLUGIN_CORE) {
        instance->context = NULL;
    }
    else {
        ctx = flb_calloc(1, sizeof(struct flb_plugin_proxy_context));
        if (!ctx) {
            flb_errno();
            flb_free(instance);
            return NULL;
        }

        ctx->proxy = plugin->proxy;

        instance->context = ctx;
    }

    instance->id    = id;
    instance->alias = NULL;
    instance->p     = plugin;
    instance->data  = data;
    instance->log_level = -1;

    mk_list_init(&instance->properties);
    mk_list_init(&instance->net_properties);
    mk_list_add(&instance->_head, &config->customs);

    return instance;
}

/* Return an instance name or alias */
const char *flb_custom_name(struct flb_custom_instance *ins)
{
    if (ins->alias) {
        return ins->alias;
    }

    return ins->name;
}

int flb_custom_plugin_property_check(struct flb_custom_instance *ins,
                                     struct flb_config *config)
{
    int ret = 0;
    struct mk_list *config_map;
    struct flb_custom_plugin *p = ins->p;

    if (p->config_map) {
        /*
         * Create a dynamic version of the configmap that will be used by the specific
         * instance in question.
         */
        config_map = flb_config_map_create(config, p->config_map);
        if (!config_map) {
            flb_error("[custom] error loading config map for '%s' plugin",
                      p->name);
            return -1;
        }
        ins->config_map = config_map;

        if ((p->flags & FLB_CUSTOM_NET_CLIENT) && (p->flags & FLB_CUSTOM_NET_SERVER)) {
                flb_error("[custom] cannot configure upstream and downstream "
                          "in the same custom plugin: '%s'",
                          p->name);
        }
        if (p->flags & FLB_CUSTOM_NET_CLIENT) {
                ins->net_config_map = flb_upstream_get_config_map(config);
                if (ins->net_config_map == NULL) {
                        flb_error("[custom] unable to load upstream properties: '%s'",
                                  p->name);
                        return -1;
                }
        }
        else if (p->flags & FLB_CUSTOM_NET_SERVER) {
                ins->net_config_map = flb_downstream_get_config_map(config);
                if (ins->net_config_map == NULL) {
                        flb_error("[custom] unable to load downstream properties: '%s'",
                                  p->name);
                        return -1;
                }
        }

        /* Validate incoming properties against config map */
        ret = flb_config_map_properties_check(ins->p->name,
                                              &ins->properties, ins->config_map);
        if (ret == -1) {
            if (config->program_name) {
                flb_helper("try the command: %s -F %s -h\n",
                           config->program_name, ins->p->name);
            }
            return -1;
        }
    }

    return 0;
}

/* Initialize all custom plugins */
int flb_custom_init_all(struct flb_config *config)
{
    int ret;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_custom_plugin *p;
    struct flb_custom_instance *ins;

    /* Iterate all active custom instance plugins */
    mk_list_foreach_safe(head, tmp, &config->customs) {
        ins = mk_list_entry(head, struct flb_custom_instance, _head);

        if (ins->log_level == -1) {
            ins->log_level = config->log->level;
        }

        p = ins->p;

#ifdef FLB_HAVE_METRICS
        /* CMetrics */
        ins->cmt = cmt_create();
        if (!ins->cmt) {
            flb_error("[custom] could not create cmetrics context: %s",
                      flb_custom_name(ins));
            return -1;
        }
#endif

        /*
         * Before to call the initialization callback, make sure that the received
         * configuration parameters are valid if the plugin is registering a config map.
         */
        if (flb_custom_plugin_property_check(ins, config) == -1) {
            flb_custom_instance_destroy(ins);
            return -1;
        }

        /* Initialize the input */
        if (p->cb_init) {
            ret = p->cb_init(ins, config, ins->data);
            if (ret != 0) {
                flb_error("Failed initialize custom %s", ins->name);
                flb_custom_instance_destroy(ins);
                return -1;
            }
        }
    }

    return 0;
}

void flb_custom_instance_destroy(struct flb_custom_instance *ins)
{
    if (!ins) {
        return;
    }

    /* destroy config map */
    if (ins->config_map) {
        flb_config_map_destroy(ins->config_map);
    }
    /* destroy net config map */
    if (ins->net_config_map) {
        flb_config_map_destroy(ins->net_config_map);
    }

    /* release properties */
    flb_kv_release(&ins->properties);
    flb_kv_release(&ins->net_properties);

    if (ins->alias) {
        flb_sds_destroy(ins->alias);
    }

#ifdef FLB_HAVE_METRICS
    if (ins->cmt) {
        cmt_destroy(ins->cmt);
    }
#endif

    mk_list_del(&ins->_head);
    flb_free(ins);
}

void flb_custom_set_context(struct flb_custom_instance *ins, void *context)
{
    ins->context = context;
}

/* Check custom plugin's log level.
 * Not for core plugins but for Golang plugins.
 * Golang plugins do not have thread-local flb_worker_ctx information. */
int flb_custom_log_check(struct flb_custom_instance *ins, int l)
{
    if (ins->log_level < l) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}
