/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_macros.h>

#define protcmp(a, b)  strncasecmp(a, b, strlen(a))

/* Copy a sub-string in a new memory buffer */
static char *copy_substr(char *str, int s)
{
    char *buf;

    buf = malloc(s + 1);
    strncpy(buf, str, s);
    buf[s] = '\0';

    return buf;
}


/*
 * It parse the out_address, split the hostname, port (if any)
 * or set the default port based on the matched protocol
 */
static int split_address(struct flb_output_plugin *plugin, char *output)
{
    int len;
    char *s, *e;

    len = strlen(plugin->name) + 3;
    if (strlen(output) <= len) {
        return -1;
    }

    s = output + len;
    if (*s == '[') {
        /* IPv6 address (RFC 3986) */
        e = strchr(++s, ']');
        if (!e) {
            return -1;
        }
        plugin->host = copy_substr(s, e - s);
        s = e + 1;
    } else {
        e = s;
        while (!(*e == '\0' || *e == ':')) {
            ++e;
        }
        if (e == s) {
            return -1;
        }
        plugin->host = copy_substr(s, e - s);
        s = e;
    }
    if (*s == ':') {
        plugin->port = atoi(++s);
    }
    else {
        plugin->port = atoi(FLB_OUTPUT_FLUENT_PORT);
    }
    return 0;
}

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
        if (out->cb_pre_run && out->active == FLB_TRUE) {
            out->cb_pre_run(out->out_context, config);
        }
    }
}

/*
 * It validate an output type given the string, it return the
 * proper type and if valid, populate the global config.
 */
int flb_output_set(struct flb_config *config, char *output)
{
    int ret = -1;
    struct flb_output_plugin *plugin;
    struct mk_list *head;

    if (!output) {
        return -1;
    }

    mk_list_foreach(head, &config->outputs) {
        plugin = mk_list_entry(head, struct flb_output_plugin, _head);

        if (check_protocol(plugin->name, output)) {
            plugin->active = FLB_TRUE;
            config->output = plugin;
            if (plugin->flags & FLB_OUTPUT_NOPROT) {
                return 0;
            }

            ret = split_address(plugin, output);
            return ret;
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
            out->cb_init(config);
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
