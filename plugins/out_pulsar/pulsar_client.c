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

#include "pulsar_client.h"

#include <math.h>

struct flb_pulsar_client *flb_pulsar_client_create(struct flb_output_instance
                                                   *ins,
                                                   struct flb_config *config)
{

    struct flb_pulsar_client *ctx =
        flb_calloc(1, sizeof(struct flb_pulsar_client));

    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->client_config = pulsar_client_configuration_create();
    ctx->producer_config = pulsar_producer_configuration_create();
    pulsar_producer_configuration_set_producer_name(ctx->producer_config,
                                                    "fluent-bit");

    flb_output_net_default("localhost", 6650, ins);

    // /tenant/namespace/topic
    char *topic = "fluent-bit";

    struct flb_uri *uri = ins->host.uri;

    if (uri && uri->count > 0) {
        struct flb_uri_field *tmp;
        topic = (tmp =
                 flb_uri_get(ins->host.uri,
                             0)) ? flb_strdup(tmp->value) : topic;
    }

    char *service_url =
        flb_malloc(9 + strlen(ins->host.name) +
                   ceil(log10(ins->host.port)) + 1);
    sprintf(service_url, "pulsar://%s:%d", ins->host.name, ins->host.port);

    ctx->client = pulsar_client_create(service_url, ctx->client_config);
    pulsar_client_create_producer(ctx->client, topic, ctx->producer_config,
                                  &ctx->producer);
    return ctx;
}

int flb_pulsar_client_destroy(struct flb_pulsar_client *ctx)
{
    if (ctx) {
        if (ctx->producer) {
            pulsar_producer_close(ctx->producer);
            pulsar_producer_free(ctx->producer);
        }

        if (ctx->producer_config) {
            pulsar_producer_configuration_free(ctx->producer_config);
        }

        if (ctx->client) {
            pulsar_client_close(ctx->client);
            pulsar_client_free(ctx->client);
        }

        if (ctx->client_config) {
            pulsar_client_configuration_free(ctx->client_config);
        }
        flb_free(ctx);
    }

    return 0;
}
