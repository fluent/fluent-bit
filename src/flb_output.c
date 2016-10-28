/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_output.h>

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_plugin_proxy.h>

#define protcmp(a, b)  strncasecmp(a, b, strlen(a))

/* Validate the the output address protocol */
static int check_protocol(char *prot, char *output)
{
    int len;

    len = strlen(prot);
    if (len > strlen(output)) {
        return 0;
    }

    if (protcmp(prot, output) != 0) {
        return 0;
    }

    return 1;
}

/* Invoke pre-run call for the output plugin */
void flb_output_pre_run(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_output_instance *ins;
    struct flb_output_plugin *p;

    mk_list_foreach(head, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        p = ins->p;
        if (p->cb_pre_run) {
            p->cb_pre_run(ins->context, config);
        }
    }
}

/* Invoke exit call for the output plugin */
void flb_output_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *tmp_prop;
    struct mk_list *head_prop;
    struct flb_config_prop *prop;
    struct flb_output_instance *ins;
    struct flb_output_plugin *p;

    mk_list_foreach_safe(head, tmp, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        p = ins->p;

        /* Check a exit callback */
        if (p->cb_exit) {
            p->cb_exit(ins->context, config);
        }

        if (ins->upstream) {
            flb_upstream_destroy(ins->upstream);
        }

        /* Remove URI context */
        if (ins->host.uri) {
            flb_uri_destroy(ins->host.uri);
        }

        flb_free(ins->host.name);
        flb_free(ins->host.address);
        flb_free(ins->match);

#ifdef FLB_HAVE_TLS
        if (ins->p->flags & FLB_IO_TLS) {
            if (ins->tls.context) {
                flb_tls_context_destroy(ins->tls.context);
            }
        }
#endif
        /* release properties */
        mk_list_foreach_safe(head_prop, tmp_prop, &ins->properties) {
            prop = mk_list_entry(head_prop, struct flb_config_prop, _head);

            flb_free(prop->key);
            flb_free(prop->val);

            mk_list_del(&prop->_head);
            flb_free(prop);
        }

        mk_list_del(&ins->_head);
        flb_free(ins);
    }
}

static inline int instance_id(struct flb_output_plugin *p,
                              struct flb_config *config) \
{
    int c = 0;
    struct mk_list *head;
    struct flb_output_instance *entry;

    mk_list_foreach(head, &config->outputs) {
        entry = mk_list_entry(head, struct flb_output_instance, _head);
        if (entry->p == p) {
            c++;
        }
    }

    return c;
}

/*
 * It validate an output type given the string, it return the
 * proper type and if valid, populate the global config.
 */
struct flb_output_instance *flb_output_new(struct flb_config *config,
                                           char *output, void *data)
{
    int ret = -1;
    int mask_id;
    struct mk_list *head;
    struct flb_output_plugin *plugin;
    struct flb_output_instance *instance = NULL;

    if (!output) {
        return NULL;
    }

    /* Get the last mask_id reported by an output instance plugin */
    if (mk_list_is_empty(&config->outputs) == 0) {
        mask_id = 0;
    }
    else {
        instance = mk_list_entry_last(&config->outputs,
                                      struct flb_output_instance,
                                      _head);
        mask_id = (instance->mask_id);
    }

    mk_list_foreach(head, &config->out_plugins) {
        plugin = mk_list_entry(head, struct flb_output_plugin, _head);
        if (!check_protocol(plugin->name, output)) {
            continue;
        }

        /* Output instance */
        instance = flb_calloc(1, sizeof(struct flb_output_instance));
        if (!instance) {
            perror("malloc");
            return NULL;
        }

        /*
         * Set mask_id: the mask_id is an unique number assigned to this
         * output instance that is used later to set in an 'unsigned 64
         * bit number' where a specific task (buffer/records) should be
         * routed.
         */
        if (mask_id == 0) {
            instance->mask_id = 1;
        }
        else {
            instance->mask_id = (mask_id * 2);
        }

        /* format name (with instance id) */
        snprintf(instance->name, sizeof(instance->name) - 1,
                 "%s.%i", plugin->name, instance_id(plugin, config));
        instance->p = plugin;

        if (plugin->type == FLB_OUTPUT_PLUGIN_CORE) {
            instance->context = NULL;
        }
        else {
            instance->context = plugin->proxy;
        }
        instance->data        = data;
        instance->upstream    = NULL;
        instance->match       = NULL;
        instance->retry_limit = 1;
        instance->host.name   = NULL;

        instance->use_tls        = FLB_FALSE;
#ifdef FLB_HAVE_TLS
        instance->tls.context    = NULL;
        instance->tls_verify     = FLB_TRUE;
        instance->tls_ca_file    = NULL;
        instance->tls_crt_file   = NULL;
        instance->tls_key_file   = NULL;
        instance->tls_key_passwd = NULL;
#endif

        if (plugin->flags & FLB_OUTPUT_NET) {
            ret = flb_net_host_set(plugin->name, &instance->host, output);
            if (ret != 0) {
                flb_free(instance);
                return NULL;
            }
        }

        mk_list_init(&instance->properties);
        mk_list_add(&instance->_head, &config->outputs);
        break;
    }

    return instance;
}

static inline int prop_key_check(char *key, char *kv, int k_len)
{
    int len;

    len = strlen(key);
    if (strncasecmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }

    return -1;
}

/* Override a configuration property for the given input_instance plugin */
int flb_output_set_property(struct flb_output_instance *out, char *k, char *v)
{
    int len;
    struct flb_config_prop *prop;

    len = strlen(k);

    /* Check if the key is a known/shared property */
    if (prop_key_check("match", k, len) == 0) {
        out->match = flb_strdup(v);
    }
    else if (prop_key_check("host", k, len) == 0) {
        out->host.name = flb_strdup(v);
    }
    else if (prop_key_check("port", k, len) == 0) {
        out->host.port = atoi(v);
    }
    else if (prop_key_check("retry_limit", k, len) == 0) {
        out->retry_limit = atoi(v);
    }
#ifdef FLB_HAVE_TLS
    else if (prop_key_check("tls", k, len) == 0) {
        if (strcasecmp(v, "true") == 0 || strcasecmp(v, "on") == 0) {
            out->use_tls = FLB_TRUE;
        }
        else {
            out->use_tls = FLB_FALSE;
        }
    }
    else if (prop_key_check("tls.verify", k, len) == 0) {
        if (strcasecmp(v, "true") == 0 || strcasecmp(v, "on") == 0) {
            out->tls_verify = FLB_TRUE;
        }
        else {
            out->tls_verify = FLB_FALSE;
        }
    }
    else if (prop_key_check("tls.ca_file", k, len) == 0) {
        out->tls_ca_file = flb_strdup(v);
    }
    else if (prop_key_check("tls.crt_file", k, len) == 0) {
        out->tls_crt_file = flb_strdup(v);
    }
    else if (prop_key_check("tls.key_file", k, len) == 0) {
        out->tls_key_file = flb_strdup(v);
    }
    else if (prop_key_check("tls.key_passwd", k, len) == 0) {
        out->tls_key_passwd = flb_strdup(v);
    }
#endif
    else {
        /* Append any remaining configuration key to prop list */
        prop = flb_malloc(sizeof(struct flb_config_prop));
        if (!prop) {
            return -1;
        }

        prop->key = flb_strdup(k);
        prop->val = flb_strdup(v);
        mk_list_add(&prop->_head, &out->properties);
    }
    return 0;
}

char *flb_output_get_property(char *key, struct flb_output_instance *i)
{
    return flb_config_prop_get(key, &i->properties);
}

/* Trigger the output plugins setup callbacks to prepare them. */
int flb_output_init(struct flb_config *config)
{
    int ret;
    struct mk_list *head;
    struct flb_output_instance *ins;
    struct flb_output_plugin *p;

    /* We need at least one output */
    if (mk_list_is_empty(&config->outputs) == 0) {
        return -1;
    }

    /* Retrieve the plugin reference */
    mk_list_foreach(head, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        p = ins->p;

#ifdef FLB_HAVE_TLS
        if (p->flags & FLB_IO_TLS) {
            ins->tls.context = flb_tls_context_new(ins->tls_verify,
                                                   ins->tls_ca_file,
                                                   ins->tls_crt_file,
                                                   ins->tls_key_file,
                                                   ins->tls_key_passwd);
        }
#endif

        if (p->type != FLB_OUTPUT_PLUGIN_CORE) {
            continue;
        }

        ret = p->cb_init(ins, config, ins->data);
        mk_list_init(&ins->th_queue);

        if (ret == -1) {
            return -1;
        }


#ifdef FLB_HAVE_STATS
        //struct flb_stats *stats;
        //stats = &out->stats;
        //stats->n = -1;
#endif
    }

    return 0;
}

/* Assign an Configuration context to an Output */
void flb_output_set_context(struct flb_output_instance *ins, void *context)
{
    ins->context = context;
}

/* Check that at least one Output is enabled */
int flb_output_check(struct flb_config *config)
{
    if (mk_list_is_empty(&config->outputs) == 0) {
        return -1;
    }
    return 0;
}
