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
    struct flb_output_plugin *out;

    mk_list_foreach(head, &config->outputs) {
        out = mk_list_entry(head, struct flb_output_plugin, _head);
        if (out->active == FLB_TRUE) {
            /* Check a pre-run callback */
            if (out->cb_pre_run) {
                out->cb_pre_run(out->out_context, config);
            }
        }
    }
}

/* Invoke exit call for the output plugin */
void flb_output_exit(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_output_plugin *out;

    mk_list_foreach(head, &config->outputs) {
        out = mk_list_entry(head, struct flb_output_plugin, _head);
        if (out->active == FLB_FALSE) {
            continue;
        }

        /* Check a exit callback */
        if (out->cb_exit) {
            out->cb_exit(out->out_context, config);
        }

        if (out->upstream) {
            flb_io_upstream_destroy(out->upstream);
        }

        if (out->host.name) {
            free(out->host.name);
        }
    }
}

/*
 * It validate an output type given the string, it return the
 * proper type and if valid, populate the global config.
 */
int flb_output_set(struct flb_config *config, char *output, void *data)
{
    int ret = -1;
    struct flb_output_plugin *plugin;
    struct mk_list *head;

    if (!output) {
        return -1;
    }

    mk_list_foreach(head, &config->out_plugins) {
        plugin = mk_list_entry(head, struct flb_output_plugin, _head);

        if (check_protocol(plugin->name, output)) {
            plugin->active = FLB_TRUE;
            plugin->data   = data;
            config->output = plugin;

            if (plugin->flags & FLB_OUTPUT_NET) {
                ret = flb_net_host_set(plugin->name, &plugin->host, output);
                return ret;
            }

            return 0;
        }
    }

    return -1;
}

/* Trigger the output plugins setup callbacks to prepare them. */
int flb_output_init(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_output_plugin *out;

    /* We need at least one output */
    if (mk_list_is_empty(&config->outputs) == 0) {
        return -1;
    }

    /* Retrieve the plugin reference */
    mk_list_foreach(head, &config->outputs) {
        out = mk_list_entry(head, struct flb_output_plugin, _head);
        if (out->active == FLB_TRUE) {
#ifdef HAVE_TLS
            if (out->flags & FLB_IO_TLS) {
                out->tls.context = flb_tls_context_new();
                mk_list_init(&out->tls.sessions);
            }
#endif
            out->cb_init(out, config, out->data);
            mk_list_init(&out->th_queue);

#ifdef HAVE_STATS
            //struct flb_stats *stats;
            //stats = &out->stats;
            //stats->n = -1;
#endif
        }
    }
    return 0;
}

static struct flb_output_plugin *plugin_lookup(char *name, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_output_plugin *plugin;

    mk_list_foreach(head, &config->outputs) {
        plugin = mk_list_entry(head, struct flb_output_plugin, _head);
        if (strncmp(plugin->name, name, strlen(name)) == 0) {
            return plugin;
        }
    }

    return NULL;
}

/* Assign an Configuration context to an Output */
int flb_output_set_context(char *name, void *out_context, struct flb_config *config)
{
    struct flb_output_plugin *plugin;

    plugin = plugin_lookup(name, config);
    if (!plugin) {
        return -1;
    }

    plugin->out_context = out_context;
    return 0;
}
