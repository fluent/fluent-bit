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

#include "pulsar_context.h"
#include "pulsar_client.h"

pulsar_result flb_pulsar_context_produce_message(struct flb_pulsar_context
                                                 *context,
                                                 pulsar_message_t * msg);

pulsar_result flb_pulsar_context_create_producer(struct flb_pulsar_context
                                                 *context);

struct flb_pulsar_context *flb_pulsar_context_create(struct
                                                     flb_output_instance *ins,
                                                     struct flb_config
                                                     *config)
{
    struct flb_pulsar_context *ctx =
        flb_calloc(1, sizeof(struct flb_pulsar_context));

    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->output_instance = ins;
    ctx->client = flb_pulsar_client_create(ins, config);

    struct flb_pulsar_context *exsiting_ctx = ins->context;
    if (exsiting_ctx) {
        flb_warn
            ("[out_pulsar] Context already established; this should only happen in Unit Tests.");
        ctx->publish_fn = exsiting_ctx->publish_fn;
        ctx->connect_fn = exsiting_ctx->connect_fn;
    }
    else {
        ctx->publish_fn = &flb_pulsar_context_produce_message;
        ctx->connect_fn = &flb_pulsar_context_create_producer;
    }

    if (!ctx->client) {
        flb_pulsar_context_destroy(ctx);
        return NULL;
    }

    return ctx;
}

pulsar_result flb_pulsar_context_create_producer(struct flb_pulsar_context *
                                                 context)
{
    return flb_pulsar_client_create_producer(context->client,
                                             context->output_instance);
}

pulsar_result flb_pulsar_context_produce_message(struct flb_pulsar_context *
                                                 context,
                                                 pulsar_message_t * msg)
{
    return flb_pulsar_client_produce_message(context->client, msg);
}

int flb_pulsar_context_destroy(struct flb_pulsar_context *ctx)
{
    if (ctx) {
        flb_pulsar_client_destroy(ctx->client);
        flb_free(ctx);
    }

    return 0;
}
