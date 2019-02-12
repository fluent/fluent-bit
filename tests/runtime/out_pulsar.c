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

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

#include "../../plugins/out_pulsar/pulsar_context.h"

/* Test functions */
#define FLB_PULSAR_TEST(name) void flb_test_pulsar_##name(void)

FLB_PULSAR_TEST(producer_config_defaults);

#define FLB_PULSAR_TEST_CASE(name) { "flb_test_pulsar_" #name, flb_test_pulsar_##name }

/* Test list */
TEST_LIST = {
    FLB_PULSAR_TEST_CASE(producer_config_defaults), {
    NULL, NULL}
};

pulsar_result pubok(struct flb_pulsar_context *context,
                    pulsar_message_t * msg)
{
    return pulsar_result_Ok;
}

pulsar_result connectok(struct flb_pulsar_context * context)
{
    return pulsar_result_Ok;
}

struct flb_pulsar_context mock_context()
{
    struct flb_pulsar_context mock;
    mock.publish_fn = &pubok;
    mock.connect_fn = &connectok;
    return mock;
}

FLB_PULSAR_TEST(producer_config_defaults)
{
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int ret;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "pulsar", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    struct flb_output_instance *instance =
        mk_list_entry_last(&ctx->config->outputs,
                           struct flb_output_instance,
                           _head);

    struct flb_pulsar_context ctxt = mock_context();
    flb_output_set_context(instance, &ctxt);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    struct flb_pulsar_context *c = instance->context;

    pulsar_producer_configuration_t *config_t = c->client->producer_config;
    TEST_CHECK(strcmp
               (pulsar_producer_configuration_get_producer_name(config_t),
                "") == 0);
    TEST_CHECK(pulsar_producer_configuration_get_compression_type(config_t) ==
               pulsar_CompressionLZ4);
    TEST_CHECK(pulsar_producer_configuration_get_block_if_queue_full(config_t)
               == 1);

    flb_stop(ctx);
    flb_destroy(ctx);
}
