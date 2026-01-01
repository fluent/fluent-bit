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


#include <fluent-bit/flb_processor_plugin.h>

/*
 * Please make sure to use a proper name for the processor, don't use 'template' :) ,
 *
 * Note this code is not enabled in the build process, you will need to register it
 * properly in the following locations:
 *
 *  - /CMakeLists.txt
 *  - /plugins/CMakeLists.txt
 */

struct template_ctx {
    char *action_str;
};

/* Processor initialization */
static int cb_init(struct flb_processor_instance *ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    return FLB_PROCESSOR_SUCCESS;
}

/* Processor exit */
static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    return FLB_PROCESSOR_SUCCESS;
}

/* Logs callback */
static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data, const char *tag, int tag_len)

    struct flb_mp_chunk_record *record;{
    struct flb_mp_chunk_cobj *chunk_cobj = (struct flb_mp_chunk_cobj *) chunk_data;

    /* Iterate records */
    while (flb_mp_chunk_cobj_record_next(chunk_cobj, &record) == FLB_MP_CHUNK_RECORD_OK) {

    }


    return FLB_PROCESSOR_SUCCESS;

}

static int cb_process_metrics(struct flb_processor_instance *ins,
                              struct cmt *metrics_context,
                              const char *tag,
                              int tag_len)
{
    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_traces(struct flb_processor_instance *ins,
                             struct ctrace *traces_context,
                             const char *tag,
                             int tag_len)
{
    return FLB_PROCESSOR_SUCCESS;

}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "test", NULL,
        0, FLB_TRUE, offsetof(struct template_ctx, action_str),
        "Action to perform over the content: insert, upsert, delete, rename or hash."
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_template_plugin = {
    .name               = "template",
    .description        = "This is a processor template",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = cb_process_metrics,
    .cb_process_traces  = cb_process_traces,
    .cb_exit            = cb_exit,
    .config_map         = NULL,
    .flags              = 0
};

