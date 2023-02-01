/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_format.h>

/*
 * Hot reload
 * ----------
 * Reload a Fluent Bit instance by using a new 'config_format' context.
 *
 *  1. As a first step, the config format is validated against the 'config maps',
 *     this will check that all configuration properties are valid.
 */

int flb_reload(flb_ctx_t *ctx, struct flb_cf *cf)
{
    int ret;
    flb_sds_t path;
    struct flb_config *config = ctx->config;
    flb_ctx_t *ctx2;
    flb_info("reloading instance pid=%lu tid=%i", getpid(), pthread_self());

    printf("[PRE STOP DUMP]\n");
    flb_cf_dump(config->cf_main);

    path = flb_sds_create(config->conf_path_file);

    /* FIXME: validate incoming 'cf' is valid before stopping current service */
    flb_info("[reload] stop everything");
    flb_stop(ctx);
    flb_destroy(ctx);


    /* Create another instance */
    ctx2 = flb_create();

    config = ctx2->config;
    flb_cf_create_from_file(config->cf_main, path);

    /* FIXME: DEBUG */
    printf("[POS STOP DUMP]\n");
    flb_cf_dump(config->cf_main);
    flb_info("[reload] start everything");

    ret = flb_start(ctx2);


    printf("reload ctx2 flb_start() => %i\n", ret);

    return 0;
}
