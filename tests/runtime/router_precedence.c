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

#include <string.h>

#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_event.h>

#include "flb_tests_runtime.h"

static const char *router_yaml_path =
#ifdef _WIN32
    FLB_TESTS_DATA_PATH "\\data\\router\\precedence.yaml";
#else
    FLB_TESTS_DATA_PATH "/data/router/precedence.yaml";
#endif

void flb_test_route_default_precedence()
{
    struct cfl_list routes;
    struct flb_cf *cf;
    struct flb_input_routes *input_routes;
    struct flb_route *route;
    struct flb_route_output *output;
    struct flb_event_chunk chunk;
    int ret;
    int match;

    cf = flb_cf_yaml_create(NULL, (char *) router_yaml_path, NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        return;
    }

    cfl_list_init(&routes);

    ret = flb_router_config_parse(cf, &routes, NULL);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_cf_destroy(cf);
        return;
    }

    input_routes = cfl_list_entry(routes.next, struct flb_input_routes, _head);
    TEST_CHECK(strcmp(input_routes->input_name, "lib") == 0);

    route = cfl_list_entry(input_routes->routes.next, struct flb_route, _head);
    TEST_CHECK(route->condition != NULL);
    TEST_CHECK(route->condition->is_default == FLB_TRUE);

    memset(&chunk, 0, sizeof(chunk));
    chunk.type = FLB_EVENT_TYPE_LOGS;

    TEST_CHECK(flb_route_condition_eval(&chunk, route) == FLB_TRUE);

    output = cfl_list_entry(route->outputs.next, struct flb_route_output, _head);
    TEST_CHECK(strcmp(output->name, "lib_route") == 0);

    match = flb_router_match("lib.input", strlen("lib.input"), "does-not-match", NULL);
    TEST_CHECK(match == FLB_FALSE);

    flb_router_routes_destroy(&routes);
    flb_cf_destroy(cf);
}

TEST_LIST = {
    {"route_default_precedence", flb_test_route_default_precedence},
    {0}
};
