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

pulsar_result flb_pulsar_context_produce_message(struct flb_pulsar_context *
                                                 context,
                                                 pulsar_message_t * msg);

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

    ctx->client = flb_pulsar_client_create(ins, config);
    ctx->publish_fn = &flb_pulsar_context_produce_message;

    if (!ctx->client) {
        flb_pulsar_context_destroy(ctx);
        return NULL;
    }

    return ctx;
}

int flb_pulsar_context_destroy(struct flb_pulsar_context *ctx)
{
    if (ctx) {
        flb_pulsar_client_destroy(ctx->client);
        flb_free(ctx);
    }

    return 0;
}

pulsar_result flb_pulsar_context_produce_message(struct flb_pulsar_context *
                                                 context,
                                                 pulsar_message_t * msg)
{
    return pulsar_producer_send(context->client->producer, msg);
}
