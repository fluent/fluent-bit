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


#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_processor.h>

#include <cfl/cfl.h>

#include "traces.h"
#include "variant_utils.h"

struct internal_processor_context {
    struct mk_list *update_list;
    struct mk_list *insert_list;
    struct mk_list *upsert_list;
    struct mk_list *convert_list;
    struct mk_list *extract_list;
    struct mk_list *delete_list;
    struct mk_list *hash_list;

    /* internal attributes ready to append */
    struct cfl_list update_attributes;
    struct cfl_list insert_attributes;
    struct cfl_list upsert_attributes;
    struct cfl_list convert_attributes;
    struct cfl_list extract_attributes;
    struct mk_list  delete_attributes;
    struct mk_list  hash_attributes;

    struct flb_processor_instance *instance;
    struct flb_config *config;
};

/*
 * LOCAL
 */

static int process_attribute_modification_list_setting(
                struct flb_processor_instance *plugin_instance,
                const char *setting_name,
                struct mk_list *source_list,
                struct mk_list *destination_list)
{
    struct flb_config_map_val *source_entry;
    struct mk_list            *iterator;
    int                        result;

    if (source_list == NULL ||
        mk_list_is_empty(source_list) == 0) {

        return 0;
    }

    flb_config_map_foreach(iterator, source_entry, source_list) {
        result = flb_slist_add(destination_list, source_entry->val.str);

        if (result != 0) {
            flb_plg_error(plugin_instance,
                          "could not append attribute name %s\n",
                          source_entry->val.str);

            return -1;
        }
    }

    return 0;
}

static int process_attribute_modification_kvlist_setting(
                struct flb_processor_instance *plugin_instance,
                const char *setting_name,
                struct mk_list *source_list,
                struct cfl_list *destination_list)
{
    struct cfl_kv             *processed_pair;
    struct flb_config_map_val *source_entry;
    struct mk_list            *iterator;
    struct flb_slist_entry    *value;
    struct flb_slist_entry    *key;

    if (source_list == NULL ||
        mk_list_is_empty(source_list) == 0) {

        return 0;
    }

    flb_config_map_foreach(iterator, source_entry, source_list) {
        if (mk_list_size(source_entry->val.list) != 2) {
            flb_plg_error(plugin_instance,
                          "'%s' expects a key and a value, "
                          "e.g: '%s version 1.8.0'",
                          setting_name, setting_name);

            return -1;
        }

        key = mk_list_entry_first(source_entry->val.list,
                                  struct flb_slist_entry, _head);

        value = mk_list_entry_last(source_entry->val.list,
                                   struct flb_slist_entry, _head);

        processed_pair = cfl_kv_item_create(destination_list,
                                            key->str,
                                            value->str);

        if (processed_pair == NULL) {
            flb_plg_error(plugin_instance,
                          "could not append attribute %s=%s\n",
                          key->str,
                          value->str);

            return -1;
        }
    }

    return 0;
}

static void destroy_context(struct internal_processor_context *context)
{
    if (context != NULL) {
        cfl_kv_release(&context->update_attributes);
        cfl_kv_release(&context->insert_attributes);
        cfl_kv_release(&context->upsert_attributes);
        cfl_kv_release(&context->convert_attributes);
        cfl_kv_release(&context->extract_attributes);
        flb_slist_destroy(&context->delete_attributes);
        flb_slist_destroy(&context->hash_attributes);

        flb_free(context);
    }
}

static struct internal_processor_context *create_context(struct flb_processor_instance *processor_instance,
                                                         struct flb_config *config)
{
    struct internal_processor_context *context;
    int                                result;

    context = flb_calloc(1, sizeof(struct internal_processor_context));
    if (!context) {
        flb_errno();
        return NULL;
    }

    context->instance = processor_instance;
    context->config = config;

    cfl_kv_init(&context->update_attributes);
    cfl_kv_init(&context->insert_attributes);
    cfl_kv_init(&context->upsert_attributes);
    cfl_kv_init(&context->convert_attributes);
    cfl_kv_init(&context->extract_attributes);
    flb_slist_create(&context->delete_attributes);
    flb_slist_create(&context->hash_attributes);

    result = flb_processor_instance_config_map_set(processor_instance, (void *) context);
    if (result == 0) {
        result = process_attribute_modification_kvlist_setting(
                    processor_instance,
                    "update",
                    context->update_list,
                    &context->update_attributes);
    }

        if (result == 0) {
            result = process_attribute_modification_kvlist_setting(
                        processor_instance,
                        "insert",
                        context->insert_list,
                        &context->insert_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_kvlist_setting(
                        processor_instance,
                        "convert",
                        context->convert_list,
                        &context->convert_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_kvlist_setting(
                        processor_instance,
                        "extract",
                        context->extract_list,
                        &context->extract_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_kvlist_setting(
                        processor_instance,
                        "upsert",
                        context->upsert_list,
                        &context->upsert_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_list_setting(
                        processor_instance,
                        "delete",
                        context->delete_list,
                        &context->delete_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_list_setting(
                        processor_instance,
                        "hash",
                        context->hash_list,
                        &context->hash_attributes);
        }

        if (result != 0) {
            destroy_context(context);

            context = NULL;
        }

    return context;
}

static int cb_init(struct flb_processor_instance *processor_instance,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    processor_instance->context = (void *) create_context(
                                            processor_instance, config);

    if (processor_instance->context == NULL) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}


static int cb_exit(struct flb_processor_instance *processor_instance)
{
    if (processor_instance != NULL &&
        processor_instance->context != NULL) {
        destroy_context(processor_instance->context);
    }

    return FLB_PROCESSOR_SUCCESS;
}



/* local declarations */





static int cb_process_traces(struct flb_processor_instance *processor_instance,
                             struct ctrace *traces_context,
                             const char *tag, int tag_len)
{
    int ret;
    struct internal_processor_context *processor_context;

    processor_context = (struct internal_processor_context *) processor_instance->context;

    ret = traces_delete_attributes(traces_context, &processor_context->delete_attributes);

    if (ret == FLB_PROCESSOR_SUCCESS) {
        ret = traces_update_attributes(traces_context, &processor_context->update_attributes);
    }

    if (ret == FLB_PROCESSOR_SUCCESS) {
        ret = traces_upsert_attributes(traces_context, &processor_context->upsert_attributes);
    }

    if (ret == FLB_PROCESSOR_SUCCESS) {
        ret = traces_insert_attributes(traces_context, &processor_context->insert_attributes);
    }

    if (ret == FLB_PROCESSOR_SUCCESS) {
        ret = traces_convert_attributes(traces_context, &processor_context->convert_attributes);
    }

    if (ret == FLB_PROCESSOR_SUCCESS) {
        ret = traces_extract_attributes(traces_context, &processor_context->extract_attributes);
    }

    if (ret == FLB_PROCESSOR_SUCCESS) {
        ret = traces_hash_attributes(traces_context, &processor_context->hash_attributes);
    }

    if (ret != FLB_PROCESSOR_SUCCESS) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_SLIST_1, "update", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                update_list),
        "Updates an attribute. Usage : 'update name value'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "insert", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                insert_list),
        "Inserts an attribute. Usage : 'insert name value'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "upsert", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                upsert_list),
        "Inserts or updates an attribute. Usage : 'upsert name value'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "convert", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                convert_list),
        "Converts an attribute. Usage : 'convert name new_type'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "extract", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                extract_list),
        "Extracts regular expression match groups as individual attributes. Usage : 'extract (?P<first_word>[^ ]*) (?P<second_word>[^ ]*)'"
    },
    {
        FLB_CONFIG_MAP_STR, "delete", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                delete_list),
        "Deletes an attribute. Usage : 'delete name'"
    },
    {
        FLB_CONFIG_MAP_STR, "hash", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                hash_list),
        "Replaces an attributes value with its SHA256 hash. Usage : 'hash name'"
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_attributes_plugin = {
    .name               = "attributes",
    .description        = "Modifies Logs and Traces attributes",
    .cb_init            = cb_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = NULL,
    .cb_process_traces  = cb_process_traces,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
