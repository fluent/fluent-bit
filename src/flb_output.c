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

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_utils.h>

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
            flb_io_upstream_destroy(ins->upstream);
        }

        if (ins->host.name) {
            free(ins->host.name);
        }

        mk_list_del(&ins->_head);
        free(ins);
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
    struct mk_list *head;
    struct flb_output_plugin *plugin;
    struct flb_output_instance *instance = NULL;

    if (!output) {
        return NULL;
    }

    mk_list_foreach(head, &config->out_plugins) {
        plugin = mk_list_entry(head, struct flb_output_plugin, _head);
        if (!check_protocol(plugin->name, output)) {
            continue;
        }

        /* Output instance */
        instance = malloc(sizeof(struct flb_output_instance));
        if (!instance) {
            perror("malloc");
            return NULL;
        }

        /* format name (with instance id) */
        snprintf(instance->name, sizeof(instance->name) - 1,
                 "%s.%i", plugin->name, instance_id(plugin, config));
        instance->p = plugin;
        instance->context = NULL;
        instance->data = data;

        if (plugin->flags & FLB_OUTPUT_NET) {
            ret = flb_net_host_set(plugin->name, &instance->host, output);
            if (ret != 0) {
                free(instance);
                return NULL;
            }
        }
        mk_list_add(&instance->_head, &config->outputs);
        break;
    }

    return instance;
}

static inline int prop_key_check(char *key, char *kv, int k_len)
{
    int len;

    len = strlen(key);
    if (strncmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }

    return -1;
}

/* Override a configuration property for the given input_instance plugin */
int flb_output_property(struct flb_output_instance *out, char *kv)
{
    int sep;
    int len;
    int k_len;
    char *value;

    /*
     * This function receives a key=value string, the 'key' aims to be a
     * known configuration property by the plugin, expected format:
     *
     *   key=value
     *
     * note: no quotes, no spaces
     */

    len = strlen(kv);
    sep = mk_string_char_search(kv, '=', len);
    if (sep == -1) {
        return -1;
    }
    k_len = sep;
    value = kv + sep + 1;

    /* Check if the key is a known/shared property */
    if (prop_key_check("tag", kv, k_len) == 0) {        /* instance.tag */
        out->tag = strdup(value);
    }
}

/* Trigger the output plugins setup callbacks to prepare them. */
int flb_output_init(struct flb_config *config)
{
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

#ifdef HAVE_TLS
        if (p->flags & FLB_IO_TLS) {
            ins->tls.context = flb_tls_context_new();
            mk_list_init(&ins->tls.sessions);
        }
#endif
        p->cb_init(ins, config, ins->data);
        mk_list_init(&ins->th_queue);

#ifdef HAVE_STATS
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
