/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <string.h>

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_plugin_alias.h>

struct flb_plugin_alias_entry {
    int plugin_type;
    const char *alias_name;
    const char *plugin_name;
};

/*
 * Table that maps user-facing aliases to plugin short names.
 *
 * Keep this table focused on backwards/forwards compatibility names where the
 * historical short name is still used internally by the plugin implementation.
 */
static struct flb_plugin_alias_entry plugin_aliases[] = {
    {
        FLB_PLUGIN_OUTPUT,
        "elasticsearch",
        "es"
    },
    {
        0,
        NULL,
        NULL
    }
};

static size_t protocol_part_length(const char *plugin_reference)
{
    char *separator;

    separator = strstr(plugin_reference, "://");
    if (separator != NULL && separator != plugin_reference) {
        return (size_t) (separator - plugin_reference);
    }

    return strlen(plugin_reference);
}

const char *flb_plugin_alias_get(int plugin_type, const char *alias_name,
                                 size_t alias_name_length)
{
    int index;
    struct flb_plugin_alias_entry *entry;

    if (alias_name == NULL || alias_name_length == 0) {
        return NULL;
    }

    for (index = 0; plugin_aliases[index].alias_name != NULL; index++) {
        entry = &plugin_aliases[index];

        if (entry->plugin_type != plugin_type) {
            continue;
        }

        if (strlen(entry->alias_name) != alias_name_length) {
            continue;
        }

        if (strncasecmp(entry->alias_name, alias_name, alias_name_length) == 0) {
            return entry->plugin_name;
        }
    }

    return NULL;
}

char *flb_plugin_alias_rewrite(int plugin_type, const char *plugin_reference)
{
    int ret;
    size_t reference_length;
    size_t protocol_length;
    size_t plugin_name_length;
    char *rewritten_reference;
    const char *plugin_name;

    if (plugin_reference == NULL) {
        return NULL;
    }

    protocol_length = protocol_part_length(plugin_reference);
    if (protocol_length == 0) {
        return NULL;
    }

    plugin_name = flb_plugin_alias_get(plugin_type, plugin_reference,
                                       protocol_length);
    if (plugin_name == NULL) {
        return NULL;
    }

    plugin_name_length = strlen(plugin_name);

    if (plugin_name_length == protocol_length &&
        strncasecmp(plugin_name, plugin_reference, protocol_length) == 0) {
        return NULL;
    }

    reference_length = strlen(plugin_reference);
    rewritten_reference = flb_calloc(1, reference_length - protocol_length +
                                        plugin_name_length + 1);
    if (rewritten_reference == NULL) {
        flb_errno();
        return FLB_PLUGIN_ALIAS_ERR;
    }

    memcpy(rewritten_reference, plugin_name, plugin_name_length);

    ret = snprintf(rewritten_reference + plugin_name_length,
                   reference_length - protocol_length + 1,
                   "%s", plugin_reference + protocol_length);
    if (ret < 0) {
        flb_free(rewritten_reference);
        return FLB_PLUGIN_ALIAS_ERR;
    }

    return rewritten_reference;
}
