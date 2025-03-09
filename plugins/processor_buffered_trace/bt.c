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

#include <stdio.h>
#include <math.h>

#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

struct trace_entry {
    struct ctrace *ctr;
    struct cfl_list _head;
};

struct buffered_trace {
    /* config properties*/
    int flush;

     /* list of buffered traces */
    struct cfl_list list;

    /* internal */
    struct flb_processor_instance *ins;
};

static void cb_flush(struct flb_config *config, void *data)
{
    struct cfl_list *head;
    struct buffered_trace *ctx;
    struct trace_entry *entry;

    ctx = (struct buffered_trace *) data;
    flb_plg_info(ctx->ins, "flush callback");

    int i = 0;
    cfl_list_foreach(head, &ctx->list) {
        entry = cfl_list_entry(head, struct trace_entry, _head);
        printf("[%i] entry ctr: %p\n", i, entry->ctr);
    }
}

static int cb_init(struct flb_processor_instance *processor_instance,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    int ret;
    struct buffered_trace *ctx;
    struct flb_sched *sched;

    /* processor context */
    ctx = flb_calloc(1, sizeof(struct buffered_trace));
    if (!ctx) {
        flb_errno();
        return FLB_PROCESSOR_FAILURE;
    }
    processor_instance->context = ctx;
    ctx->ins = processor_instance;
    cfl_list_init(&ctx->list);

    /* get the scheduler context */
    sched = flb_sched_ctx_get();
    if (!sched) {
        flb_plg_error(ctx->ins, "could not get scheduler context");
        return -1;
    }

    /* load config map */
    flb_processor_instance_config_map_set(ctx->ins, ctx);

    /* set a timer callback */
    ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                    ctx->flush, cb_flush,
                                    ctx, NULL);
    printf("cb_create() = %i\n", ret);

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_traces(struct flb_processor_instance *ins,
                             struct ctrace *in_ctr,
                             struct ctrace **out_ctr,
                             const char *tag,
                             int tag_len)
{
    int ret;
    off_t offset = 0;
    char *out_buf = NULL;
    size_t out_size = 0;
    struct ctrace *ctr_copy;
    struct buffered_trace *ctx;
    struct trace_entry *entry;

    ctx = ins->context;

    /* copy the original ctrace in another buffer (the caller will destory it */
    ret = ctr_encode_msgpack_create(in_ctr, &out_buf, &out_size);
    if (ret != 0) {
        return FLB_PROCESSOR_FAILURE;
    }

    ret = ctr_decode_msgpack_create(&ctr_copy, out_buf, out_size, &offset);
    if (ret != 0) {
        return FLB_PROCESSOR_FAILURE;
    }

    entry = flb_malloc(sizeof(struct trace_entry));
    if (!entry) {
        flb_errno();
        ctr_decode_msgpack_destroy(out_buf);
        ctr_destroy(ctr_copy);
        return -1;
    }
    entry->ctr = ctr_copy;
    cfl_list_add(&entry->_head, &ctx->list);

    *out_ctr = NULL;
    return FLB_PROCESSOR_SUCCESS;

}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
   {
    FLB_CONFIG_MAP_TIME, "flush", "5000",
    0, FLB_TRUE, offsetof(struct buffered_trace, flush),
    "Flush time for queued traces"
   },

   /* EOF */
    {0}
};

struct flb_processor_plugin processor_buffered_trace_plugin = {
    .name               = "buffered_trace",
    .description        = "Test buffered trace",
    .cb_init            = cb_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = NULL,
    .cb_process_traces  = cb_process_traces,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
