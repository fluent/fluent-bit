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


#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_utils.h>

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
    flb_sds_t file = NULL;
    struct flb_config *old_config = ctx->config;
    struct flb_config *new_config;
    flb_ctx_t *new_ctx;
    struct flb_cf *new_cf;

    flb_info("reloading instance pid=%lu tid=%i", getpid(), pthread_self());

    printf("[PRE STOP DUMP]\n");
    flb_cf_dump(old_config->cf_main);

    if (old_config->conf_path_file) {
        file = flb_sds_create(old_config->conf_path_file);
    }

    /* FIXME: validate incoming 'cf' is valid before stopping current service */
    flb_info("[reload] stop everything");
    flb_stop(ctx);
    flb_destroy(ctx);

    /* Create another instance */
    new_ctx = flb_create();

    new_config = new_ctx->config;
    new_cf = new_config->cf_main;

    /* Create another config format context */
    if (file != NULL) {
        new_cf = flb_cf_create_from_file(new_config->cf_main, file);

        if (!new_cf) {
            flb_sds_destroy(file);

            return -1;
        }

        ret = flb_config_load_config_format(new_config, new_cf);
        if (ret != 0) {
            flb_sds_destroy(file);

            return -1;
        }
    }

    if (file != NULL) {
        new_config->conf_path_file = file;
    }
    new_config->cf_main = new_cf;

    /* FIXME: DEBUG */
    printf("[POS STOP DUMP]\n");
    flb_cf_dump(new_config->cf_main);
    flb_info("[reload] start everything");

    ret = flb_start(new_ctx);


    printf("reload new_ctx flb_start() => %i\n", ret);

    return 0;
}
