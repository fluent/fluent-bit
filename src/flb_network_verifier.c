/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_network_verifier.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_utils.h>

static int instance_id(struct flb_config *config)
{
    struct flb_network_verifier_instance *entry;

    if (mk_list_size(&config->network_verifiers) == 0) {
        return 0;
    }

    entry = mk_list_entry_last(&config->network_verifiers, 
                               struct flb_network_verifier_instance,
                               _head);
    return (entry->id + 1);
}

const char *flb_network_verifier_get_alias(
    struct flb_network_verifier_instance *ins)
{
    if (ins->alias) {
        return ins->alias;
    }

    return ins->name;
}

static int prop_key_check(const char *key, const char *kv, int k_len)
{
    int len = strlen(key);
    if (strncasecmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }

    return -1;
}

/* Initialize all network verify plugins */
int flb_network_verifier_init_all(struct flb_config *config)
{
    int ret;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_network_verifier_plugin *plugin;
    struct flb_network_verifier_instance *ins;

    /* Iterate all active network verify instance plugins */
    mk_list_foreach_safe(head, tmp, &config->network_verifiers) {
        ins = mk_list_entry(head, struct flb_network_verifier_instance, 
                            _head);

        if (ins->log_level == -1) {
            ins->log_level = config->log->level;
        }

        plugin = ins->plugin;

        /*
         * Before to call the initialization callback, make sure that the received
         * configuration parameters are valid if the plugin is registering a config map.
         */
        if (flb_network_verifier_plugin_property_check(ins, config) == -1) {
            flb_network_verifier_instance_destroy(ins);
            return -1;
        }

        /* Initialize the input */
        if (plugin->cb_init) {
            ret = plugin->cb_init(ins, config);
            if (ret != 0) {
                flb_error("Failed initialize network_verifier %s", ins->name);
                flb_network_verifier_instance_destroy(ins);
                return -1;
            }
        }
    }

    return 0;
}

struct flb_network_verifier_instance *flb_network_verifier_new(
    struct flb_config *config, const char *name)
{
    int id;
    struct mk_list *head;
    struct flb_network_verifier_plugin *plugin;
    struct flb_network_verifier_instance *instance = NULL;

    if (!name) {
        return NULL;
    }

    mk_list_foreach(head, &config->network_verifier_plugins) {
        plugin = mk_list_entry(head, struct flb_network_verifier_plugin, _head);
        if (strcmp(plugin->name, name) == 0) {
            break;
        }
        plugin = NULL;
    }

    if (!plugin) {
        return NULL;
    }

    instance = flb_calloc(1, sizeof(struct flb_network_verifier_instance));
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

    instance->id    = id;
    instance->alias = NULL;
    instance->plugin = plugin;
    instance->log_level = -1;

    mk_list_init(&instance->properties);
    mk_list_add(&instance->_head, &config->network_verifiers);

    return instance;
}

/* Override a configuration property for the given input_instance plugin */
int flb_network_verifier_set_property(struct flb_network_verifier_instance *ins,
                                         const char *k, const char *v)
{
    int len;
    int ret;
    flb_sds_t tmp;
    struct flb_kv *kv;
    const struct flb_config *config = ins->config;

    len = strlen(k);
    tmp = flb_env_var_translate(config->env, v);
    if (tmp) {
        if (strlen(tmp) == 0) {
            flb_sds_destroy(tmp);
            tmp = NULL;
        }
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

int flb_network_verifier_plugin_property_check(
    struct flb_network_verifier_instance *ins, struct flb_config *config)
{
    int ret = 0;
    struct mk_list *config_map;
    struct flb_network_verifier_plugin *plugin = ins->plugin;

    if (plugin->config_map) {
        /*
         * Create a dynamic version of the configmap that will be used by the specific
         * instance in question.
         */
        config_map = flb_config_map_create(config, plugin->config_map);
        if (!config_map) {
            flb_error("[network_verifier] error loading config map for '%s' plugin",
                      plugin->name);
            return -1;
        }
        ins->config_map = config_map;

        if (!ins->alias || flb_sds_len(ins->alias) == 0) {
            flb_error("[network_verifier] NO alias property for %s network_verifier instance.",
                        ins->name);
            return -1;
        }

        /* Validate incoming properties against config map */
        ret = flb_config_map_properties_check(ins->plugin->name,
                                              &ins->properties, ins->config_map);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

void flb_network_verifier_instance_exit(struct flb_network_verifier_instance *ins,
                                           struct flb_config *config)
{
    struct flb_network_verifier_plugin *plugin = ins->plugin;
    if (plugin->cb_exit && ins->context) {
        plugin->cb_exit(ins->context, config);
    }
}

/* Invoke exit call for the network_verifier plugin */
void flb_network_verifier_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_network_verifier_instance *ins;
    struct flb_network_verifier_plugin *plugin;

    mk_list_foreach_safe(head, tmp, &config->network_verifiers) {
        ins = mk_list_entry(head, struct flb_network_verifier_instance, _head);
        plugin = ins->plugin;
        if (!plugin) {
            continue;
        }
        flb_network_verifier_instance_exit(ins, config);
        flb_network_verifier_instance_destroy(ins);
    }
}


void flb_network_verifier_instance_destroy(
    struct flb_network_verifier_instance *ins)
{
    if (!ins) {
        return;
    }

    /* destroy config map */
    if (ins->config_map) {
        flb_config_map_destroy(ins->config_map);
    }

    /* release properties */
    flb_kv_release(&ins->properties);

    if (ins->alias) {
        flb_sds_destroy(ins->alias);
    }

    mk_list_del(&ins->_head);
    flb_free(ins);
}

const struct flb_network_verifier_instance *find_network_verifier_instance(
                struct flb_config *config,
                const char* alias)
{
    struct mk_list *head;
    struct flb_network_verifier_instance *verifier;

    if (!alias || strlen(alias) == 0) {
        return NULL;
    }

    mk_list_foreach(head, &config->network_verifiers) {
        verifier = mk_list_entry(head, struct flb_network_verifier_instance, _head);
        if (strcmp(verifier->alias, alias) == 0) {
            return verifier;
        }
    }

    return NULL;
}
