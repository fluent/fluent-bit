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
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_plugin_alias.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_output.h>

#include <string.h>

#include "flb_tests_internal.h"

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
    flb_uri_destroy(host.uri);
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

    instance = flb_output_new(config, "elasticsearch", NULL, FLB_TRUE);
    if (!TEST_CHECK(instance != NULL)) {
        TEST_MSG("could not instantiate aliased output plugin");
        flb_config_exit(config);
        return;
    }

    if (!TEST_CHECK(strcmp(instance->p->name, "es") == 0)) {
        TEST_MSG("unexpected output plugin instantiated for alias: %s",
                 instance->p->name);
    }

    flb_output_instance_destroy(instance);
    flb_config_exit(config);
}

TEST_LIST = {
    { "plugin_alias_lookup_test", plugin_alias_lookup_test },
    { "plugin_alias_rewrite_test", plugin_alias_rewrite_test },
    { "network_alias_address_parse_test", network_alias_address_parse_test },
    { "output_alias_instantiation_test", output_alias_instantiation_test },
    { 0 }
};
