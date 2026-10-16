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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_plugin_alias.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_processor.h>

#include <string.h>

#include "flb_tests_internal.h"

static struct flb_plugin_alias_entry custom_aliases[] = {
    { FLB_PLUGIN_INPUT, "tailing", "tail" },
    { FLB_PLUGIN_INPUT, "httping", "http" },
    { FLB_PLUGIN_FILTER, "grepper", "grep" },
    { FLB_PLUGIN_PROCESSOR, "countering", "content_modifier" },
    { FLB_PLUGIN_OUTPUT, "elasticsearch", "es_custom" },
    { 0, NULL, NULL }
};

static struct flb_plugin_alias_entry colliding_aliases[] = {
    { FLB_PLUGIN_INPUT, "dummy", "tail" },
    { FLB_PLUGIN_FILTER, "grep", "modify" },
    { FLB_PLUGIN_PROCESSOR, "content_modifier", "labels" },
    { FLB_PLUGIN_OUTPUT, "stdout", "null" },
    { 0, NULL, NULL }
};

void plugin_alias_lookup_test()
{
    const char *alias_target;

    alias_target = flb_plugin_alias_get(FLB_PLUGIN_OUTPUT, "elasticsearch",
                                        strlen("elasticsearch"));
    if (!TEST_CHECK(alias_target != NULL)) {
        TEST_MSG("output plugin alias was not resolved");
        return;
    }

    if (!TEST_CHECK(strcmp(alias_target, "es") == 0)) {
        TEST_MSG("unexpected alias target: %s", alias_target);
    }
}

void plugin_alias_custom_map_test()
{
    const char *alias_target;

    flb_plugin_alias_set_custom_entries(custom_aliases);

    alias_target = flb_plugin_alias_get(FLB_PLUGIN_INPUT, "tailing",
                                        strlen("tailing"));
    TEST_CHECK(alias_target != NULL);
    TEST_CHECK(strcmp(alias_target, "tail") == 0);

    alias_target = flb_plugin_alias_get(FLB_PLUGIN_FILTER, "grepper",
                                        strlen("grepper"));
    TEST_CHECK(alias_target != NULL);
    TEST_CHECK(strcmp(alias_target, "grep") == 0);

    alias_target = flb_plugin_alias_get(FLB_PLUGIN_OUTPUT, "elasticsearch",
                                        strlen("elasticsearch"));
    TEST_CHECK(alias_target != NULL);
    TEST_CHECK(strcmp(alias_target, "es_custom") == 0);

    flb_plugin_alias_reset_custom_entries();

    alias_target = flb_plugin_alias_get(FLB_PLUGIN_OUTPUT, "elasticsearch",
                                        strlen("elasticsearch"));
    TEST_CHECK(alias_target != NULL);
    TEST_CHECK(strcmp(alias_target, "es") == 0);
}

void plugin_alias_rewrite_test()
{
    char *rewritten_name;

    rewritten_name = flb_plugin_alias_rewrite(FLB_PLUGIN_OUTPUT,
                                              "elasticsearch://127.0.0.1:9200");
    if (!TEST_CHECK(rewritten_name != FLB_PLUGIN_ALIAS_ERR)) {
        TEST_MSG("error while rewriting output plugin alias");
        return;
    }
    if (!TEST_CHECK(rewritten_name != NULL)) {
        TEST_MSG("could not rewrite output plugin alias");
        return;
    }

    if (!TEST_CHECK(strcmp(rewritten_name, "es://127.0.0.1:9200") == 0)) {
        TEST_MSG("unexpected rewritten output plugin name: %s", rewritten_name);
    }

    flb_free(rewritten_name);
}

void network_alias_address_parse_test()
{
    int ret;
    struct flb_net_host host;

    ret = flb_net_host_set("es", &host, "elasticsearch://127.0.0.1:9200/path");
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("could not parse alias output address");
        return;
    }

    if (!TEST_CHECK(strcmp(host.name, "127.0.0.1") == 0)) {
        TEST_MSG("unexpected host name parsed from alias output address: %s",
                 host.name);
    }

    if (!TEST_CHECK(host.port == 9200)) {
        TEST_MSG("unexpected host port parsed from alias output address: %d",
                 host.port);
    }

    flb_sds_destroy(host.name);
    flb_sds_destroy(host.listen);
    if (host.uri != NULL) {
        flb_uri_destroy(host.uri);
    }
    flb_sds_destroy(host.address);

    ret = flb_net_host_set("very_long_original_plugin", &host,
                           "x://localhost:1234");
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("could not parse a URI with an alias shorter than its target");
        return;
    }
    TEST_CHECK(host.name != NULL && strcmp(host.name, "localhost") == 0);
    TEST_CHECK(host.port == 1234);

    flb_sds_destroy(host.name);
    flb_sds_destroy(host.listen);
    if (host.uri != NULL) {
        flb_uri_destroy(host.uri);
    }
    flb_sds_destroy(host.address);
}

void output_alias_instantiation_test()
{
    struct flb_config *config;
    struct flb_output_instance *instance;

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        TEST_MSG("could not initialize config context");
        return;
    }

    instance = flb_output_new(config,
                              "elasticsearch://127.0.0.1:9200/test",
                              NULL, FLB_TRUE);
    if (!TEST_CHECK(instance != NULL)) {
        TEST_MSG("could not instantiate aliased output plugin");
        flb_config_exit(config);
        return;
    }

    if (!TEST_CHECK(strcmp(instance->p->name, "es") == 0)) {
        TEST_MSG("unexpected output plugin instantiated for alias: %s",
                 instance->p->name);
    }
    TEST_CHECK(instance->host.name != NULL &&
               strcmp(instance->host.name, "127.0.0.1") == 0);
    TEST_CHECK(instance->host.port == 9200);

    flb_output_instance_destroy(instance);

    instance = flb_output_new(config, "es", NULL, FLB_TRUE);
    if (!TEST_CHECK(instance != NULL && strcmp(instance->p->name, "es") == 0)) {
        TEST_MSG("could not instantiate output plugin by its original name");
        flb_config_exit(config);
        return;
    }
    flb_output_instance_destroy(instance);
    flb_config_exit(config);
}

void input_alias_uri_instantiation_test()
{
    struct flb_config *config;
    struct flb_input_instance *alias_instance;
    struct flb_input_instance *original_instance;

    alias_instance = NULL;
    original_instance = NULL;
    flb_plugin_alias_set_custom_entries(custom_aliases);

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        goto cleanup;
    }

    alias_instance = flb_input_new(config, "httping://127.0.0.1:9880",
                                   NULL, FLB_TRUE);
    if (!TEST_CHECK(alias_instance != NULL &&
                    strcmp(alias_instance->p->name, "http") == 0)) {
        TEST_MSG("could not instantiate URI input through its alias");
        goto cleanup;
    }
    TEST_CHECK(alias_instance->host.name != NULL &&
               strcmp(alias_instance->host.name, "127.0.0.1") == 0);
    TEST_CHECK(alias_instance->host.port == 9880);

    original_instance = flb_input_new(config, "http://127.0.0.1:9881",
                                      NULL, FLB_TRUE);
    if (!TEST_CHECK(original_instance != NULL &&
                    strcmp(original_instance->p->name, "http") == 0)) {
        TEST_MSG("could not instantiate URI input through its original name");
        goto cleanup;
    }
    TEST_CHECK(original_instance->host.name != NULL &&
               strcmp(original_instance->host.name, "127.0.0.1") == 0);
    TEST_CHECK(original_instance->host.port == 9881);

cleanup:
    if (original_instance != NULL) {
        flb_input_instance_destroy(original_instance);
    }
    if (alias_instance != NULL) {
        flb_input_instance_destroy(alias_instance);
    }
    if (config != NULL) {
        flb_config_exit(config);
    }
    flb_plugin_alias_reset_custom_entries();
}

void plugin_alias_instance_types_test()
{
    struct flb_config *config;
    struct flb_input_instance *input;
    struct flb_filter_instance *filter;
    struct flb_processor *processor;
    struct flb_processor_unit *filter_unit;
    struct flb_processor_unit *native_unit;

    input = NULL;
    filter = NULL;
    processor = NULL;
    flb_plugin_alias_set_custom_entries(custom_aliases);

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        TEST_MSG("could not initialize config context");
        goto cleanup;
    }

    input = flb_input_new(config, "tailing", NULL, FLB_TRUE);
    if (!TEST_CHECK(input != NULL && strcmp(input->p->name, "tail") == 0)) {
        TEST_MSG("could not instantiate an input plugin through its alias");
        goto cleanup;
    }

    filter = flb_filter_new(config, "grepper", NULL);
    if (!TEST_CHECK(filter != NULL && strcmp(filter->p->name, "grep") == 0)) {
        TEST_MSG("could not instantiate a filter plugin through its alias");
        goto cleanup;
    }

    processor = flb_processor_create(config, "alias_test", NULL, FLB_PLUGIN_INPUT);
    if (!TEST_CHECK(processor != NULL)) {
        TEST_MSG("could not create processor context");
        goto cleanup;
    }

    filter_unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS,
                                            "grepper");
    if (!TEST_CHECK(filter_unit != NULL &&
                    filter_unit->unit_type == FLB_PROCESSOR_UNIT_FILTER)) {
        TEST_MSG("could not instantiate a processor filter through its alias");
        goto cleanup;
    }

    native_unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS,
                                            "countering");
    if (!TEST_CHECK(native_unit != NULL &&
                    native_unit->unit_type == FLB_PROCESSOR_UNIT_NATIVE)) {
        TEST_MSG("could not instantiate a native processor through its alias");
    }

cleanup:
    if (processor != NULL) {
        flb_processor_destroy(processor);
    }
    if (filter != NULL) {
        flb_filter_instance_destroy(filter);
    }
    if (input != NULL) {
        flb_input_instance_destroy(input);
    }
    if (config != NULL) {
        flb_config_exit(config);
    }
    flb_plugin_alias_reset_custom_entries();
}

void plugin_original_name_precedence_test()
{
    struct flb_config *config;
    struct flb_input_instance *input;
    struct flb_filter_instance *filter;
    struct flb_output_instance *output;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;

    input = NULL;
    filter = NULL;
    output = NULL;
    processor = NULL;
    flb_plugin_alias_set_custom_entries(colliding_aliases);

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        TEST_MSG("could not initialize config context");
        goto cleanup;
    }

    input = flb_input_new(config, "dummy", NULL, FLB_TRUE);
    TEST_CHECK(input != NULL && strcmp(input->p->name, "dummy") == 0);

    filter = flb_filter_new(config, "grep", NULL);
    TEST_CHECK(filter != NULL && strcmp(filter->p->name, "grep") == 0);

    output = flb_output_new(config, "stdout", NULL, FLB_TRUE);
    TEST_CHECK(output != NULL && strcmp(output->p->name, "stdout") == 0);

    processor = flb_processor_create(config, "precedence_test", NULL,
                                     FLB_PLUGIN_INPUT);
    if (processor != NULL) {
        unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS,
                                         "content_modifier");
        TEST_CHECK(unit != NULL &&
                   strcmp(((struct flb_processor_instance *) unit->ctx)->p->name,
                          "content_modifier") == 0);
    }
    else {
        TEST_CHECK(processor != NULL);
    }

cleanup:
    if (processor != NULL) {
        flb_processor_destroy(processor);
    }
    if (output != NULL) {
        flb_output_instance_destroy(output);
    }
    if (filter != NULL) {
        flb_filter_instance_destroy(filter);
    }
    if (input != NULL) {
        flb_input_instance_destroy(input);
    }
    if (config != NULL) {
        flb_config_exit(config);
    }
    flb_plugin_alias_reset_custom_entries();
}

TEST_LIST = {
    { "plugin_alias_lookup_test", plugin_alias_lookup_test },
    { "plugin_alias_custom_map_test", plugin_alias_custom_map_test },
    { "plugin_alias_rewrite_test", plugin_alias_rewrite_test },
    { "network_alias_address_parse_test", network_alias_address_parse_test },
    { "output_alias_instantiation_test", output_alias_instantiation_test },
    { "input_alias_uri_instantiation_test", input_alias_uri_instantiation_test },
    { "plugin_alias_instance_types_test", plugin_alias_instance_types_test },
    { "plugin_original_name_precedence_test", plugin_original_name_precedence_test },
    { 0 }
};
