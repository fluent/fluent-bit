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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_plugin_proxy.h>
#include <fluent-bit/flb_http_client_debug.h>

FLB_TLS_DEFINE(struct flb_libco_out_params, flb_libco_params);

void flb_output_prepare()
{
    FLB_TLS_INIT(flb_libco_params);
}

/* Validate the the output address protocol */
static int check_protocol(const char *prot, const char *output)
{
    int len;
    char *p;

    p = strstr(output, "://");
    if (p && p != output) {
        len = p - output;
    }
    else {
        len = strlen(output);
    }

    if (strlen(prot) != len) {
        return 0;
    }

    /* Output plugin match */
    if (strncasecmp(prot, output, len) == 0) {
        return 1;
    }

    return 0;
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
    flb_kv_release(&ins->properties);

#ifdef FLB_HAVE_TLS
    if (ins->tls_vhost) {
        flb_sds_destroy(ins->tls_vhost);
    }
    if (ins->tls_ca_path) {
        flb_sds_destroy(ins->tls_ca_path);
    }
    if (ins->tls_ca_file) {
        flb_sds_destroy(ins->tls_ca_file);
    }
    if (ins->tls_crt_file) {
        flb_sds_destroy(ins->tls_crt_file);
    }
    if (ins->tls_key_file) {
        flb_sds_destroy(ins->tls_key_file);
    }
    if (ins->tls_key_passwd) {
        flb_sds_destroy(ins->tls_key_passwd);
    }
#endif
}

int flb_output_instance_destroy(struct flb_output_instance *ins)
{
    if (ins->alias) {
        flb_sds_destroy(ins->alias);
    }

    /* Remove URI context */
    if (ins->host.uri) {
        flb_uri_destroy(ins->host.uri);
    }

    flb_sds_destroy(ins->host.name);
    flb_sds_destroy(ins->host.address);
    flb_sds_destroy(ins->host.listen);
    flb_sds_destroy(ins->match);

#ifdef FLB_HAVE_REGEX
        if (ins->match_regex) {
            flb_regex_destroy(ins->match_regex);
        }
#endif

#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
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

    /* destroy callback context */
    if (ins->callback) {
        flb_callback_destroy(ins->callback);
    }

    /* destroy config map */
    if (ins->config_map) {
        flb_config_map_destroy(ins->config_map);
    }

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
    void *params;

    mk_list_foreach_safe(head, tmp, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        p = ins->p;

        /* Check a exit callback */
        if (p->cb_exit) {
            if(!p->proxy) {
                p->cb_exit(ins->context, config);
            }
            else {
                p->cb_exit(p, ins->context);
            }
        }

        if (ins->upstream) {
            flb_upstream_destroy(ins->upstream);
        }

        flb_output_instance_destroy(ins);
    }

    params = FLB_TLS_GET(flb_libco_params);
    if (params) {
        flb_free(params);
    }
}

static inline int instance_id(struct flb_config *config)
{
    struct flb_output_instance *ins;

    if (mk_list_size(&config->outputs) == 0) {
        return 0;
    }

    ins = mk_list_entry_last(&config->outputs, struct flb_output_instance,
                             _head);
    return (ins->id + 1);
}

/*
 * It validate an output type given the string, it return the
 * proper type and if valid, populate the global config.
 */
struct flb_output_instance *flb_output_new(struct flb_config *config,
                                           const char *output, void *data)
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
        flb_errno();
        return NULL;
    }
    instance->config = config;
    instance->log_level = -1;
    /*
     * Set mask_id: the mask_id is an unique number assigned to this
     * output instance that is used later to set in an 'unsigned 64
     * bit number' where a specific task (buffer/records) should be
     * routed.
     *
     * note: This value is different than instance id.
     */
    if (mask_id == 0) {
        instance->mask_id = 1;
    }
    else {
        instance->mask_id = (mask_id * 2);
    }

    /* Retrieve an instance id for the output instance */
    instance->id = instance_id(config);

    /* format name (with instance id) */
    snprintf(instance->name, sizeof(instance->name) - 1,
             "%s.%i", plugin->name, instance->id);
    instance->p = plugin;
    instance->callback = flb_callback_create(instance->name);
    if (!instance->callback) {
        flb_free(instance);
        return NULL;
    }

    if (plugin->type == FLB_OUTPUT_PLUGIN_CORE) {
        instance->context = NULL;
    }
    else {
        struct flb_plugin_proxy_context *ctx;

        ctx = flb_calloc(1, sizeof(struct flb_plugin_proxy_context));
        if (!ctx) {
            flb_errno();
            flb_free(instance);
            return NULL;
        }

        ctx->proxy = plugin->proxy;

        instance->context = ctx;
    }

    instance->alias       = NULL;
    instance->flags       = instance->p->flags;
    instance->data        = data;
    instance->upstream    = NULL;
    instance->match       = NULL;
#ifdef FLB_HAVE_REGEX
    instance->match_regex = NULL;
#endif
    instance->retry_limit = 1;
    instance->host.name   = NULL;
    instance->host.address = NULL;

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

    /* Keepalive feature to reuse Upstream connections */
    instance->keepalive = FLB_FALSE;
    instance->keepalive_timeout = FLB_OUTPUT_KA_TIMEOUT;

#ifdef FLB_HAVE_TLS
    instance->tls.context           = NULL;
    instance->tls.handshake_timeout = FLB_UPSTREAM_TLS_HANDSHAKE_TIMEOUT;
    instance->tls_debug             = -1;
    instance->tls_verify            = FLB_TRUE;
    instance->tls_vhost             = NULL;
    instance->tls_ca_path           = NULL;
    instance->tls_ca_file           = NULL;
    instance->tls_crt_file          = NULL;
    instance->tls_key_file          = NULL;
    instance->tls_key_passwd        = NULL;
#endif

    if (plugin->flags & FLB_OUTPUT_NET) {
        ret = flb_net_host_set(plugin->name, &instance->host, output);
        if (ret != 0) {
            flb_free(instance);
            return NULL;
        }
    }

    flb_kv_init(&instance->properties);
    mk_list_add(&instance->_head, &config->outputs);

    return instance;
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

/* Override a configuration property for the given input_instance plugin */
int flb_output_set_property(struct flb_output_instance *ins,
                            const char *k, const char *v)
{
    int len;
    int ret;
    flb_sds_t tmp;
    struct flb_kv *kv;

    len = strlen(k);
    tmp = flb_env_var_translate(ins->config->env, v);
    if (tmp) {
        if (strlen(tmp) == 0) {
            flb_sds_destroy(tmp);
            tmp = NULL;
        }
    }

    /* Check if the key is a known/shared property */
    if (prop_key_check("match", k, len) == 0) {
        ins->match = tmp;
    }
#ifdef FLB_HAVE_REGEX
    else if (prop_key_check("match_regex", k, len) == 0 && tmp) {
        ins->match_regex = flb_regex_create(tmp);
        flb_sds_destroy(tmp);
    }
#endif
    else if (prop_key_check("alias", k, len) == 0 && tmp) {
        ins->alias = tmp;
    }
    else if (prop_key_check("log_level", k, len) == 0 && tmp) {
        ret = flb_log_get_level_str(tmp);
        flb_sds_destroy(tmp);
        if (ret == -1) {
            return -1;
        }
        ins->log_level = ret;
    }
    else if (prop_key_check("host", k, len) == 0) {
        ins->host.name = tmp;
    }
    else if (prop_key_check("port", k, len) == 0) {
        if (tmp) {
            ins->host.port = atoi(tmp);
            flb_sds_destroy(tmp);
        }
        else {
            ins->host.port = 0;
        }
    }
    else if (prop_key_check("keepalive", k, len) == 0) {
        if (tmp) {
            ins->keepalive = flb_utils_bool(tmp);
            flb_sds_destroy(tmp);
        }
        else {
            ins->keepalive = FLB_FALSE;
        }
    }
    else if (prop_key_check("keepalive_timeout", k, len) == 0) {
        if (tmp) {
            ins->keepalive_timeout = atoi(tmp);
            flb_sds_destroy(tmp);
        }
        else {
            ins->keepalive_timeout = 10;
        }
    }
    else if (prop_key_check("ipv6", k, len) == 0 && tmp) {
        ins->host.ipv6 = flb_utils_bool(tmp);
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("retry_limit", k, len) == 0) {
        if (tmp) {
            if (strcasecmp(tmp, "false") == 0 ||
                strcasecmp(tmp, "off") == 0) {
                /* No limits for retries */
                ins->retry_limit = -1;
            }
            else {
                ins->retry_limit = atoi(tmp);
            }
            flb_sds_destroy(tmp);
        }
        else {
            ins->retry_limit = 0;
        }
    }
#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
    else if (strncasecmp("_debug.http.", k, 12) == 0 && tmp) {
        ret = flb_http_client_debug_property_is_valid((char *) k, tmp);
        if (ret == FLB_TRUE) {
            kv = flb_kv_item_create(&ins->properties, (char *) k, NULL);
            if (!kv) {
                if (tmp) {
                    flb_sds_destroy(tmp);
                }
                return -1;
            }
            kv->val = tmp;
        }
        else {
            flb_error("[config] invalid property '%s' on instance '%s'",
                      k, flb_output_name(ins));
            flb_sds_destroy(tmp);
        }
    }
#endif
#ifdef FLB_HAVE_TLS
    else if (prop_key_check("tls", k, len) == 0 && tmp) {
        if (strcasecmp(tmp, "true") == 0 || strcasecmp(tmp, "on") == 0) {
            if ((ins->flags & FLB_IO_TLS) == 0) {
                flb_error("[config] %s don't support TLS", ins->name);
                flb_sds_destroy(tmp);
                return -1;
            }

            ins->use_tls = FLB_TRUE;
        }
        else {
            ins->use_tls = FLB_FALSE;
        }
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("tls.verify", k, len) == 0 && tmp) {
        if (strcasecmp(tmp, "true") == 0 || strcasecmp(tmp, "on") == 0) {
            ins->tls_verify = FLB_TRUE;
        }
        else {
            ins->tls_verify = FLB_FALSE;
        }
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("tls.debug", k, len) == 0 && tmp) {
        ins->tls_debug = atoi(tmp);
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("tls.vhost", k, len) == 0) {
        ins->tls_vhost = tmp;
    }
    else if (prop_key_check("tls.ca_path", k, len) == 0) {
        ins->tls_ca_path = tmp;
    }
    else if (prop_key_check("tls.ca_file", k, len) == 0) {
        ins->tls_ca_file = tmp;
    }
    else if (prop_key_check("tls.crt_file", k, len) == 0) {
        ins->tls_crt_file = tmp;
    }
    else if (prop_key_check("tls.key_file", k, len) == 0) {
        ins->tls_key_file = tmp;
    }
    else if (prop_key_check("tls.key_passwd", k, len) == 0) {
        ins->tls_key_passwd = tmp;
    }
    else if (prop_key_check("tls.handshake_timeout", k, len) == 0 && tmp) {
        ins->tls.handshake_timeout = atoi(tmp);
        flb_sds_destroy(tmp);
    }
#endif
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

/* Configure a default hostname and TCP port if they are not set */
void flb_output_net_default(const char *host, const int port,
                            struct flb_output_instance *ins)
{
    /* Set default network configuration */
    if (!ins->host.name) {
        ins->host.name = flb_sds_create(host);
    }
    if (ins->host.port == 0) {
        ins->host.port = port;
    }
}

/* Return an instance name or alias */
const char *flb_output_name(struct flb_output_instance *ins)
{
    if (ins->alias) {
        return ins->alias;
    }

    return ins->name;
}

const char *flb_output_get_property(const char *key, struct flb_output_instance *ins)
{
    return flb_config_prop_get(key, &ins->properties);
}

/* Trigger the output plugins setup callbacks to prepare them. */
int flb_output_init_all(struct flb_config *config)
{
    int ret;
#ifdef FLB_HAVE_METRICS
    const char *name;
#endif
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *config_map;
    struct flb_output_instance *ins;
    struct flb_output_plugin *p;

    /* Retrieve the plugin reference */
    mk_list_foreach_safe(head, tmp, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        if (ins->log_level == -1) {
            ins->log_level = config->log->level;
        }
        p = ins->p;

        /* Metrics */
#ifdef FLB_HAVE_METRICS
        /* Get name or alias for the instance */
        name = flb_output_name(ins);

        ins->metrics = flb_metrics_create(name);
        if (ins->metrics) {
            flb_metrics_add(FLB_METRIC_OUT_OK_RECORDS,
                            "proc_records", ins->metrics);
            flb_metrics_add(FLB_METRIC_OUT_OK_BYTES,
                            "proc_bytes", ins->metrics);
            flb_metrics_add(FLB_METRIC_OUT_ERROR,
                            "errors", ins->metrics);
            flb_metrics_add(FLB_METRIC_OUT_RETRY,
                            "retries", ins->metrics);
            flb_metrics_add(FLB_METRIC_OUT_RETRY_FAILED,
                        "retries_failed", ins->metrics);
        }
#endif

#ifdef FLB_HAVE_PROXY_GO
        /* Proxy plugins have their own initialization */
        if (p->type == FLB_OUTPUT_PLUGIN_PROXY) {
            ret = flb_plugin_proxy_init(p->proxy, ins, config);
            if (ret == -1) {
                return -1;
            }
            continue;
        }
#endif

#ifdef FLB_HAVE_TLS
        if (ins->use_tls == FLB_TRUE) {
            ins->tls.context = flb_tls_context_new(ins->tls_verify,
                                                   ins->tls_debug,
                                                   ins->tls_vhost,
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
        /*
         * Before to call the initialization callback, make sure that the received
         * configuration parameters are valid if the plugin is registering a config map.
         */
        if (p->config_map) {
            /*
             * Create a dynamic version of the configmap that will be used by the specific
             * instance in question.
             */
            config_map = flb_config_map_create(config, p->config_map);
            if (!config_map) {
                flb_error("[output] error loading config map for '%s' plugin",
                          p->name);
                return -1;
            }
            ins->config_map = config_map;

            /* Validate incoming properties against config map */
            ret = flb_config_map_properties_check(ins->p->name,
                                                  &ins->properties, ins->config_map);
            if (ret == -1) {
                if (config->program_name) {
                    flb_helper("try the command: %s -o %s -h\n",
                               config->program_name, ins->p->name);
                }
                flb_output_instance_destroy(ins);
                return -1;
            }
        }

        /* Initialize plugin through it 'init callback' */
        ret = p->cb_init(ins, config, ins->data);
        mk_list_init(&ins->th_queue);
        if (ret == -1) {
            flb_error("[output] Failed to initialize '%s' plugin",
                      p->name);
            return -1;
        }
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

/*
 * Output plugins might have enabled certain features that have not been passed
 * directly to the upstream context. In order to avoid let plugins validate specific
 * variables from the instance context like tls, tls.x, keepalive, etc, we populate
 * them directly through this function.
 */
int flb_output_upstream_set(struct flb_upstream *u, struct flb_output_instance *ins)
{
    int flags = 0;

    if (!u) {
        return -1;
    }

    /* TLS */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        flags |= FLB_IO_TLS;
    }
    else {
        flags |= FLB_IO_TCP;
    }
#else
    flags |= FLB_IO_TCP;
#endif

    /* IPv6 */
    if (ins->host.ipv6 == FLB_TRUE) {
        flags |= FLB_IO_IPV6;
    }

    /* KeepAlive */
    if (ins->keepalive == FLB_TRUE) {
        flags |= FLB_IO_TCP_KA;

        /* Keepalive timeout */
        u->ka_timeout = ins->keepalive_timeout;
    }

    /* Set flags */
    u->flags |= flags;
    return 0;
}

/*
 * Helper function to set HTTP callbacks using the output instance 'callback'
 * context.
 */
int flb_output_set_http_debug_callbacks(struct flb_output_instance *ins)
{
#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
    return flb_http_client_debug_setup(ins->callback, &ins->properties);
#else
    return 0;
#endif
}
