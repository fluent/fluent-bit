/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
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

static void flb_output_free_properties(struct flb_output_instance *ins)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_config_prop *prop;

    mk_list_foreach_safe(head, tmp, &ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        flb_free(prop->key);
        flb_free(prop->val);

        mk_list_del(&prop->_head);
        flb_free(prop);
    }

#ifdef FLB_HAVE_TLS
    if (ins->tls_ca_path) {
        flb_free(ins->tls_ca_path);
    }
    if (ins->tls_ca_file) {
        flb_free(ins->tls_ca_file);
    }
    if (ins->tls_crt_file) {
        flb_free(ins->tls_crt_file);
    }
    if (ins->tls_key_file) {
        flb_free(ins->tls_key_file);
    }
    if (ins->tls_key_passwd) {
        flb_free(ins->tls_key_passwd);
    }
#endif
}

int flb_output_instance_destroy(struct flb_output_instance *ins)
{
    /* Remove URI context */
    if (ins->host.uri) {
        flb_uri_destroy(ins->host.uri);
    }

    flb_free(ins->host.name);
    flb_free(ins->host.address);
    flb_free(ins->match);

#ifdef FLB_HAVE_TLS
    if (ins->flags & FLB_IO_TLS) {
        if (ins->tls.context) {
            flb_tls_context_destroy(ins->tls.context);
        }
    }
#endif

    /* Remove metrics */
#ifdef FLB_HAVE_METRICS
    if (ins->metrics) {
        flb_metrics_destroy(ins->metrics);
    }
#endif

    /* release properties */
    flb_output_free_properties(ins);

    mk_list_del(&ins->_head);
    flb_free(ins);

    return 0;
}

/* Invoke exit call for the output plugin */
void flb_output_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
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

        flb_output_instance_destroy(ins);
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
    int flags = 0;
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
        if (check_protocol(plugin->name, output)) {
            break;
        }
        plugin = NULL;
    }

    if (!plugin) {
        return NULL;
    }

    /* Create and load instance */
    instance = flb_calloc(1, sizeof(struct flb_output_instance));
    if (!instance) {
        perror("malloc");
        return NULL;
    }
    instance->config = config;

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

    instance->flags       = instance->p->flags;
    instance->data        = data;
    instance->upstream    = NULL;
    instance->match       = NULL;
    instance->retry_limit = 1;
    instance->host.name   = NULL;

    /* Parent plugin flags */
    flags = instance->flags;
    if (flags & FLB_IO_TCP) {
        instance->use_tls = FLB_FALSE;
    }
    else if (flags & FLB_IO_TLS) {
        instance->use_tls = FLB_TRUE;
    }
    else if (flags & FLB_IO_OPT_TLS) {
        /* TLS must be enabled manually in the config */
        instance->use_tls = FLB_FALSE;
        instance->flags |= FLB_IO_TLS;
    }

#ifdef FLB_HAVE_TLS
    instance->tls.context    = NULL;
    instance->tls_debug      = -1;
    instance->tls_verify     = FLB_TRUE;
    instance->tls_ca_path    = NULL;
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

    /* Metrics */
#ifdef FLB_HAVE_METRICS
    instance->metrics = flb_metrics_create(instance->name);
    if (instance->metrics) {
        flb_metrics_add(FLB_METRIC_OUT_OK_RECORDS, "proc_records", instance->metrics);
        flb_metrics_add(FLB_METRIC_OUT_OK_BYTES, "proc_bytes", instance->metrics);
        flb_metrics_add(FLB_METRIC_OUT_ERROR, "errors", instance->metrics);
        flb_metrics_add(FLB_METRIC_OUT_RETRY, "retries", instance->metrics);
        flb_metrics_add(FLB_METRIC_OUT_RETRY_FAILED,
                        "retries_failed", instance->metrics);
    }
#endif

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
    char *tmp;
    struct flb_config_prop *prop;

    len = strlen(k);
    tmp = flb_env_var_translate(out->config->env, v);
    if (tmp) {
        if (strlen(tmp) == 0) {
            flb_free(tmp);
            tmp = NULL;
        }
    }

    /* Check if the key is a known/shared property */
    if (prop_key_check("match", k, len) == 0) {
        out->match = tmp;
    }
    else if (prop_key_check("host", k, len) == 0) {
        out->host.name = tmp;
    }
    else if (prop_key_check("port", k, len) == 0) {
        if (tmp) {
            out->host.port = atoi(tmp);
            flb_free(tmp);
        }
        else {
            out->host.port = 0;
        }
    }
    else if (prop_key_check("ipv6", k, len) == 0 && tmp) {
        out->host.ipv6 = flb_utils_bool(tmp);
        flb_free(tmp);
    }
    else if (prop_key_check("retry_limit", k, len) == 0) {
        if (tmp) {
            if (strcasecmp(tmp, "false") == 0 ||
                strcasecmp(tmp, "off") == 0) {
                /* No limits for retries */
                out->retry_limit = -1;
            }
            else {
                out->retry_limit = atoi(tmp);
            }
            flb_free(tmp);
        }
        else {
            out->retry_limit = 0;
        }
    }
#ifdef FLB_HAVE_TLS
    else if (prop_key_check("tls", k, len) == 0 && tmp) {
        if (strcasecmp(tmp, "true") == 0 || strcasecmp(tmp, "on") == 0) {
            if ((out->flags & FLB_IO_TLS) == 0) {
                flb_error("[config] %s don't support TLS", out->name);
                flb_free(tmp);
                return -1;
            }

            out->use_tls = FLB_TRUE;
        }
        else {
            out->use_tls = FLB_FALSE;
        }
        flb_free(tmp);
    }
    else if (prop_key_check("tls.verify", k, len) == 0 && tmp) {
        if (strcasecmp(tmp, "true") == 0 || strcasecmp(tmp, "on") == 0) {
            out->tls_verify = FLB_TRUE;
        }
        else {
            out->tls_verify = FLB_FALSE;
        }
        flb_free(tmp);
    }
    else if (prop_key_check("tls.debug", k, len) == 0 && tmp) {
        out->tls_debug = atoi(tmp);
        flb_free(tmp);
    }
    else if (prop_key_check("tls.ca_path", k, len) == 0) {
        out->tls_ca_path = tmp;
    }
    else if (prop_key_check("tls.ca_file", k, len) == 0) {
        out->tls_ca_file = tmp;
    }
    else if (prop_key_check("tls.crt_file", k, len) == 0) {
        out->tls_crt_file = tmp;
    }
    else if (prop_key_check("tls.key_file", k, len) == 0) {
        out->tls_key_file = tmp;
    }
    else if (prop_key_check("tls.key_passwd", k, len) == 0) {
        out->tls_key_passwd = tmp;
    }
#endif
    else {
        /* Append any remaining configuration key to prop list */
        prop = flb_malloc(sizeof(struct flb_config_prop));
        if (!prop) {
            if (tmp) {
                flb_free(tmp);
            }
            return -1;
        }

        prop->key = flb_strdup(k);
        prop->val = tmp;
        mk_list_add(&prop->_head, &out->properties);
    }

    return 0;
}

/* Configure a default hostname and TCP port if they are not set */
void flb_output_net_default(char *host, int port,
                            struct flb_output_instance *o_ins)
{
    /* Set default network configuration */
    if (!o_ins->host.name) {
        o_ins->host.name = flb_strdup(host);
    }
    if (o_ins->host.port == 0) {
        o_ins->host.port = port;
    }
}

char *flb_output_get_property(char *key, struct flb_output_instance *o_ins)
{
    return flb_config_prop_get(key, &o_ins->properties);
}

/* Trigger the output plugins setup callbacks to prepare them. */
int flb_output_init(struct flb_config *config)
{
    int ret;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_output_instance *ins;
    struct flb_output_plugin *p;

    /* We need at least one output */
    if (mk_list_is_empty(&config->outputs) == 0) {
        return -1;
    }

    /* Retrieve the plugin reference */
    mk_list_foreach_safe(head, tmp, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        p = ins->p;

#ifdef FLB_HAVE_PROXY_GO
        /* Proxy plugins have heir own initialization */
        if (p->type == FLB_OUTPUT_PLUGIN_PROXY) {
            flb_plugin_proxy_init(p->proxy, ins, config);
            continue;
        }
#endif

#ifdef FLB_HAVE_TLS
        if (ins->flags & FLB_IO_TLS) {
            ins->tls.context = flb_tls_context_new(ins->tls_verify,
                                                   ins->tls_debug,
                                                   ins->tls_ca_path,
                                                   ins->tls_ca_file,
                                                   ins->tls_crt_file,
                                                   ins->tls_key_file,
                                                   ins->tls_key_passwd);
            if (!ins->tls.context) {
                flb_error("[output %s] error initializing TLS context",
                          ins->name);
                flb_output_instance_destroy(ins);
                return -1;
            }
        }
#endif
        ret = p->cb_init(ins, config, ins->data);
        mk_list_init(&ins->th_queue);
        if (ret == -1) {
            flb_error("[output] Failed to initialize '%s' plugin",
                      p->name);
            return -1;
        }
    }

    /* Iterate list of proxies plugins */
    mk_list_foreach(head, &config->proxies) {
        //proxy = mk_list_entry(head, struct flb_plugin_proxy, _head);
        //flb_plugin_proxy_init(proxy, config);
        //printf("load proxy name = %s\n", proxy->name);
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
