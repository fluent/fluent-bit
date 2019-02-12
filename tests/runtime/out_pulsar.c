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
#include "../../plugins/out_pulsar/pulsar_config.h"

/* Test functions */
#define FLB_PULSAR_TEST(name) void flb_test_pulsar_##name(void)

FLB_PULSAR_TEST(producer_config_defaults);
FLB_PULSAR_TEST(producer_config_send_timeout);
FLB_PULSAR_TEST(producer_config_compression_type_none);
FLB_PULSAR_TEST(producer_config_compression_type_zlib);
FLB_PULSAR_TEST(producer_config_compression_type_lz4);
FLB_PULSAR_TEST(producer_config_compression_type_invalid);
FLB_PULSAR_TEST(producer_config_max_pending_messages);
FLB_PULSAR_TEST(producer_config_batching_settings);
FLB_PULSAR_TEST(client_config_defaults);
FLB_PULSAR_TEST(client_config_auth_tls);
FLB_PULSAR_TEST(client_config_auth_athenz);
FLB_PULSAR_TEST(client_config_auth_token);
FLB_PULSAR_TEST(client_config_auth_custom);
FLB_PULSAR_TEST(client_config_with_tls_on_defaults);
FLB_PULSAR_TEST(client_config_with_tls_options);

#define FLB_PULSAR_TEST_ENTRY(name) { "flb_test_pulsar_" #name, flb_test_pulsar_##name }

/* Test list */
TEST_LIST = {
    FLB_PULSAR_TEST_ENTRY(producer_config_defaults),
        FLB_PULSAR_TEST_ENTRY(producer_config_send_timeout),
        FLB_PULSAR_TEST_ENTRY(producer_config_compression_type_none),
        FLB_PULSAR_TEST_ENTRY(producer_config_compression_type_zlib),
        FLB_PULSAR_TEST_ENTRY(producer_config_compression_type_lz4),
        FLB_PULSAR_TEST_ENTRY(producer_config_compression_type_invalid),
        FLB_PULSAR_TEST_ENTRY(producer_config_max_pending_messages),
        FLB_PULSAR_TEST_ENTRY(producer_config_batching_settings),
        FLB_PULSAR_TEST_ENTRY(client_config_defaults),
        FLB_PULSAR_TEST_ENTRY(client_config_auth_tls),
        FLB_PULSAR_TEST_ENTRY(client_config_auth_athenz),
        FLB_PULSAR_TEST_ENTRY(client_config_auth_token),
        FLB_PULSAR_TEST_ENTRY(client_config_auth_custom),
        FLB_PULSAR_TEST_ENTRY(client_config_with_tls_on_defaults),
        FLB_PULSAR_TEST_ENTRY(client_config_with_tls_options), {
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

static flb_ctx_t *ctx = NULL;

struct flb_output_instance *prepare_output_instance()
{
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "pulsar", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    return mk_list_entry_last(&ctx->config->outputs,
                              struct flb_output_instance, _head);
}

void tear_down(void)
{
    if (ctx) {
        flb_destroy(ctx);
    }
}

FLB_PULSAR_TEST(producer_config_defaults)
{
    struct flb_output_instance *instance = prepare_output_instance();

    pulsar_producer_configuration_t *producer_cfg =
        flb_pulsar_config_producer_config_create(instance);

    TEST_CHECK(strcmp
               (pulsar_producer_configuration_get_producer_name(producer_cfg),
                "") == 0);
    TEST_CHECK(pulsar_producer_configuration_get_compression_type
               (producer_cfg) == pulsar_CompressionLZ4);
    TEST_CHECK(pulsar_producer_configuration_get_block_if_queue_full
               (producer_cfg) == 1);
    TEST_CHECK(pulsar_producer_configuration_get_batching_enabled
               (producer_cfg) == 0);

    pulsar_producer_configuration_free(producer_cfg);
    tear_down();
}

FLB_PULSAR_TEST(producer_config_send_timeout)
{
    struct flb_output_instance *instance = prepare_output_instance();

    flb_output_set_property(instance, "send_timeout", "1234");
    pulsar_producer_configuration_t *producer_cfg =
        flb_pulsar_config_producer_config_create(instance);

    TEST_CHECK(pulsar_producer_configuration_get_send_timeout(producer_cfg) ==
               1234);

    pulsar_producer_configuration_free(producer_cfg);
    tear_down();
}

FLB_PULSAR_TEST(producer_config_compression_type_none)
{
    struct flb_output_instance *instance = prepare_output_instance();

    pulsar_producer_configuration_t *producer_cfg;

    flb_output_set_property(instance, "compression_type", "None");
    producer_cfg = flb_pulsar_config_producer_config_create(instance);
    TEST_CHECK(pulsar_producer_configuration_get_compression_type
               (producer_cfg) == pulsar_CompressionNone);

    pulsar_producer_configuration_free(producer_cfg);
    tear_down();
}

FLB_PULSAR_TEST(producer_config_compression_type_zlib)
{
    struct flb_output_instance *instance = prepare_output_instance();

    pulsar_producer_configuration_t *producer_cfg;

    flb_output_set_property(instance, "compression_type", "zLIB");
    producer_cfg = flb_pulsar_config_producer_config_create(instance);
    TEST_CHECK(pulsar_producer_configuration_get_compression_type
               (producer_cfg) == pulsar_CompressionZLib);

    pulsar_producer_configuration_free(producer_cfg);
    tear_down();
}

FLB_PULSAR_TEST(producer_config_compression_type_lz4)
{
    struct flb_output_instance *instance = prepare_output_instance();

    pulsar_producer_configuration_t *producer_cfg;
    flb_output_set_property(instance, "compression_type", "lz4");
    producer_cfg = flb_pulsar_config_producer_config_create(instance);
    TEST_CHECK(pulsar_producer_configuration_get_compression_type
               (producer_cfg) == pulsar_CompressionLZ4);

    pulsar_producer_configuration_free(producer_cfg);
    tear_down();
}

FLB_PULSAR_TEST(producer_config_compression_type_invalid)
{
    struct flb_output_instance *instance = prepare_output_instance();

    pulsar_producer_configuration_t *producer_cfg;
    flb_output_set_property(instance, "compression_type", "something-bogus");
    producer_cfg = flb_pulsar_config_producer_config_create(instance);
    TEST_CHECK(pulsar_producer_configuration_get_compression_type
               (producer_cfg) == pulsar_CompressionLZ4);

    pulsar_producer_configuration_free(producer_cfg);
    tear_down();
}

FLB_PULSAR_TEST(producer_config_max_pending_messages)
{
    struct flb_output_instance *instance = prepare_output_instance();

    pulsar_producer_configuration_t *producer_cfg;
    flb_output_set_property(instance, "max_pending_messages", "42");
    producer_cfg = flb_pulsar_config_producer_config_create(instance);
    TEST_CHECK(pulsar_producer_configuration_get_max_pending_messages
               (producer_cfg) == 42);

    pulsar_producer_configuration_free(producer_cfg);
    tear_down();
}

FLB_PULSAR_TEST(producer_config_batching_settings)
{
    struct flb_output_instance *instance = prepare_output_instance();

    pulsar_producer_configuration_t *producer_cfg;
    flb_output_set_property(instance, "batching_enabled", "on");
    flb_output_set_property(instance, "batching_max_publish_delay_ms", "314");

    producer_cfg = flb_pulsar_config_producer_config_create(instance);
    TEST_CHECK(pulsar_producer_configuration_get_batching_enabled
               (producer_cfg) == 1);
    TEST_CHECK(pulsar_producer_configuration_get_batching_max_publish_delay_ms
               (producer_cfg) == 314);

    pulsar_producer_configuration_free(producer_cfg);
    tear_down();
}

FLB_PULSAR_TEST(client_config_defaults)
{
    struct flb_output_instance *instance = prepare_output_instance();

    pulsar_client_configuration_t *client_cfg =
        flb_pulsar_config_client_config_create(instance);

    TEST_CHECK_(client_cfg != NULL,
                "This test should check that auth method defaults to none, "
                "but there is no method to get the auth method from the config.");
    TEST_CHECK(pulsar_client_configuration_is_use_tls(client_cfg) == 0);

    pulsar_client_configuration_free(client_cfg);
    tear_down();
}

FLB_PULSAR_TEST(client_config_auth_tls)
{
    struct flb_output_instance *instance = prepare_output_instance();

    flb_output_set_property(instance, "auth_method", "TLS");
    flb_output_set_property(instance, "auth_params", "I'm a tls auth param");
    pulsar_client_configuration_t *client_cfg =
        flb_pulsar_config_client_config_create(instance);

    TEST_CHECK_(client_cfg != NULL,
                "This test should check that auth method is correctly 'tls', "
                "but the Pulsar C API provides no means to do so.");

    pulsar_client_configuration_free(client_cfg);
    tear_down();
}

FLB_PULSAR_TEST(client_config_auth_token)
{
    struct flb_output_instance *instance = prepare_output_instance();

    flb_output_set_property(instance, "auth_method", "toKeN");
    flb_output_set_property(instance, "auth_params",
                            "I'm a token auth param");
    pulsar_client_configuration_t *client_cfg =
        flb_pulsar_config_client_config_create(instance);

    TEST_CHECK_(client_cfg != NULL,
                "This test should check that auth method is correctly 'token', "
                "but the Pulsar C API provides no means to do so.");

    pulsar_client_configuration_free(client_cfg);
    tear_down();
}

FLB_PULSAR_TEST(client_config_auth_athenz)
{
    struct flb_output_instance *instance = prepare_output_instance();

    flb_output_set_property(instance, "auth_method", "Athenz");
    flb_output_set_property(instance, "auth_params",
                            "{ \"tenantDomain\": \"fake\","
                            "  \"tenantService\": \"fake\","
                            "  \"providerDomain\": \"fake\","
                            "  \"privateKey\": \"fake\","
                            "  \"ztsUrl\": \"fake\" }");
    pulsar_client_configuration_t *client_cfg =
        flb_pulsar_config_client_config_create(instance);

    TEST_CHECK_(client_cfg != NULL,
                "This test should check that auth method is correctly 'athenz', "
                "but the Pulsar C API provides no means to do so.");

    pulsar_client_configuration_free(client_cfg);
    tear_down();
}

FLB_PULSAR_TEST(client_config_auth_custom)
{
    struct flb_output_instance *instance = prepare_output_instance();

    flb_output_set_property(instance, "auth_method", "/path/to/custom.so");
    flb_output_set_property(instance, "auth_params",
                            "I'm a custom auth param");
    pulsar_client_configuration_t *client_cfg =
        flb_pulsar_config_client_config_create(instance);

    TEST_CHECK_(client_cfg != NULL,
                "This test should check that auth method supports a custom path,"
                "but the Pulsar C API provides no means to do so.");

    pulsar_client_configuration_free(client_cfg);
    tear_down();
}

FLB_PULSAR_TEST(client_config_with_tls_on_defaults)
{
    struct flb_output_instance *instance = prepare_output_instance();
    flb_output_set_property(instance, "tls", "on");

    pulsar_client_configuration_t *client_cfg =
        flb_pulsar_config_client_config_create(instance);
    TEST_CHECK(pulsar_client_configuration_is_use_tls(client_cfg) == 1);
    TEST_CHECK(pulsar_client_configuration_is_tls_allow_insecure_connection
               (client_cfg) == 0);
    TEST_CHECK(strcmp
               (pulsar_client_configuration_get_tls_trust_certs_file_path
                (client_cfg), "") == 0);

    pulsar_client_configuration_free(client_cfg);
    tear_down();
}

FLB_PULSAR_TEST(client_config_with_tls_options)
{
    struct flb_output_instance *instance = prepare_output_instance();
    flb_output_set_property(instance, "tls", "on");
    flb_output_set_property(instance, "tls.verify", "off");
    flb_output_set_property(instance, "tls.ca_file", "/path/to/certs");

    pulsar_client_configuration_t *client_cfg =
        flb_pulsar_config_client_config_create(instance);
    TEST_CHECK(pulsar_client_configuration_is_use_tls(client_cfg) == 1);
    TEST_CHECK(pulsar_client_configuration_is_tls_allow_insecure_connection
               (client_cfg) == 1);
    TEST_CHECK(strcmp
               (pulsar_client_configuration_get_tls_trust_certs_file_path
                (client_cfg), "/path/to/certs") == 0);

    pulsar_client_configuration_free(client_cfg);
    tear_down();
}
