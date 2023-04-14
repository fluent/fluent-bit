/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <cfl/cfl.h>

struct internal_processor_context {
    /* config reader for 'label' */
    struct mk_list *provided_labels;

    /* internal labels ready to append */
    struct cfl_list processed_labels;

    struct flb_processor_instance *instance;
    struct flb_config *config;
};


static int process_labels(struct internal_processor_context *context)
{
    struct flb_kv             *processed_pair;
    struct flb_config_map_val *source_pair;
    struct mk_list            *iterator;
    struct flb_slist_entry    *value;
    struct flb_slist_entry    *key;

    if (context->provided_labels == NULL ||
        mk_list_is_empty(context->provided_labels) == 0) {

        return 0;
    }

    /* iterate all 'add_label' definitions */
    flb_config_map_foreach(iterator, source_pair, context->provided_labels) {
        if (mk_list_size(source_pair->val.list) != 2) {
            flb_plg_error(context->instance,
                          "'label' expects a key and a value, "
                          "e.g: 'label version 1.8.0'");

            return -1;
        }

        key = mk_list_entry_first(source_pair->val.list,
                                  struct flb_slist_entry, _head);

        value = mk_list_entry_last(source_pair->val.list,
                                   struct flb_slist_entry, _head);

        processed_pair = cfl_kv_item_create(&context->processed_labels,
                                            key->str,
                                            value->str);

        if (processed_pair == NULL) {
            flb_plg_error(context->instance,
                          "could not append label %s=%s\n",
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
        cfl_kv_release(&context->processed_labels);

        flb_free(context);
    }
}

static struct internal_processor_context *
        create_context(struct flb_processor_instance *p_ins,
                       struct flb_config *config)
{
    struct internal_processor_context *context;
    int                                result;

    context = flb_calloc(1, sizeof(struct internal_processor_context));

    if (context == NULL) {
        context->instance = p_ins;
        context->config = config;

        cfl_kv_init(&context->processed_labels);

        result = flb_output_config_map_set(p_ins, (void *) context);

        if (result == 0) {
            result = process_labels(context);
        }

        if (result != 0) {
            destroy_context(context);

            context = NULL;
        }
    }
    else {
        flb_errno();
    }

    return context;
}



static int cb_init(struct flb_processor_instance *p_ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    p_ins->context = (void *) create_context(p_ins, config);

    if (p_ins->context == NULL) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_metrics(struct flb_processor_instance *p_ins,
                              struct cmt *metrics_context,
                              const char *tag,
                              int tag_len)
{
    printf("cb_process_metrics : %p\n", metrics_context);

    cmt_label_add(metrics_context, "TEST LABEL NAME", "LABEL VALUE");

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_SLIST_1, "label", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                provided_labels),
        "Adds a custom label to the metrics use format: 'label name value'"
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_add_labels_plugin = {
    .name               = "add_labels",
    .description        = "Adds labels to a metrics context",
    .cb_init            = cb_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = cb_process_metrics,
    .cb_process_traces  = NULL,
    .cb_exit            = NULL,
    .config_map         = config_map,
    .flags              = 0
};
