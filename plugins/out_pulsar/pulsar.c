/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>

#include <stdio.h>

#include <pulsar/c/client.h>

#include "pulsar_context.h"

static int cb_pulsar_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_pulsar_context *ctx = flb_pulsar_context_create(ins, config);
    if (!ctx) {
        flb_error("[out_pulsar] cannot initialize plugin");
        return -1;
    }

    flb_output_set_context(ins, ctx);
    return 0;
}

static int cb_pulsar_pre_run(void *out_context, struct flb_config *config)
{
    struct flb_pulsar_context *ctx = out_context;
    if (ctx->connect_fn(ctx) != pulsar_result_Ok) {
        return -1;
    }
    return 0;
}

static int produce_message(struct flb_time *tm, msgpack_object * map,
                           struct flb_pulsar_context *ctx,
                           struct flb_config *config)
{
    const size_t INITIAL_BUFFER_ALLOCATION = 1024;
    char *const out_buf =
        flb_msgpack_to_json_str(INITIAL_BUFFER_ALLOCATION, map);
    int result = FLB_ERROR;

    if (!out_buf) {
        flb_error("[out_pulsar] error encoding to JSON");
        return FLB_ERROR;
    }

    pulsar_message_t *msg = pulsar_message_create();
    pulsar_message_set_content(msg, out_buf, strlen(out_buf));

    pulsar_result publish_result = ctx->publish_fn(ctx, msg);
    switch (publish_result) {
    case pulsar_result_Ok:
        result = FLB_OK;
        break;
    case pulsar_result_Timeout:
    case pulsar_result_ProducerBlockedQuotaExceededException:
    case pulsar_result_ProducerBlockedQuotaExceededError:
        flb_warn("[out_pulsar] Message failed to send due to %s; will retry.",
                 pulsar_result_str(publish_result));
        result = FLB_RETRY;
        break;
    default:
        flb_error("[out_pulsar] Message failed due to %s.",
                  pulsar_result_str(publish_result));
        break;
    }

    flb_free(out_buf);
    return result;
}

static void cb_pulsar_flush(void *data, size_t bytes,
                            char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context, struct flb_config *config)
{
    int ret = FLB_OK;
    size_t off = 0;
    struct flb_pulsar_context *ctx = out_context;
    struct flb_time tms;
    msgpack_object *obj;
    msgpack_unpacked result;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        ret = produce_message(&tms, obj, ctx, config);
        if (ret != FLB_OK) {
            break;
        }
    }

    msgpack_unpacked_destroy(&result);
    FLB_OUTPUT_RETURN(ret);
}

static int cb_pulsar_exit(void *data, struct flb_config *config)
{
    struct flb_pulsar_context *ctx = data;
    flb_pulsar_context_destroy(ctx);
    return 0;
}

struct flb_output_plugin out_pulsar_plugin = {
    .name = "pulsar",
    .description = "Pulsar Native Client",
    .cb_init = cb_pulsar_init,
    .cb_pre_run = cb_pulsar_pre_run,
    .cb_flush = cb_pulsar_flush,
    .cb_exit = cb_pulsar_exit,
    .flags = FLB_OUTPUT_NET | FLB_IO_OPT_TLS
};
