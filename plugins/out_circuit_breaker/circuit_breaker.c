/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/* Circuit Breaker context, only works with one instance */
struct circuit_breaker_ctx {
    int requests;
    int total_successes;
    int total_failures;
    int consecutive_successes;
    int consecutive_failures;
    struct flb_output_instance *ins; /* plugin instance */
};

static int cb_circuit_breaker_init(struct flb_output_instance *ins,
                                   struct flb_config *config,
                                   void *data)
{
    (void) config;
    (void) data;
    struct circuit_breaker_ctx *ctx;

}

static int cb_circuit_breaker_exit(void *data, struct flb_config *config)
{
    struct circuit_breaker_ctx *ctx = data;
    (void) config;

    flb_free(ctx);
    return 0;
}