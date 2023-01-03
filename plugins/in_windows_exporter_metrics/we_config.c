/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include "we.h"

struct flb_we *flb_we_config_create(struct flb_input_instance *ins,
                                    struct flb_config *config)
{
    int ret;
    struct flb_we *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_we));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->allowing_disk_regex = NULL;
    ctx->denying_disk_regex = NULL;
    ctx->allowing_nic_regex = NULL;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Process allow/deny regex rules */
    if (ctx->raw_allowing_disk != NULL) {
        ctx->allowing_disk_regex = flb_regex_create(ctx->raw_allowing_disk);
    }

    if (ctx->raw_denying_disk != NULL) {
        ctx->denying_disk_regex = flb_regex_create(ctx->raw_denying_disk);
    }

    if (ctx->raw_allowing_nic != NULL) {
        ctx->allowing_nic_regex = flb_regex_create(ctx->raw_allowing_nic);
    }

    ctx->cmt = cmt_create();
    if (!ctx->cmt) {
        flb_plg_error(ins, "could not initialize CMetrics");
        flb_free(ctx);
        return NULL;
    }

    return ctx;
}

void flb_we_config_destroy(struct flb_we *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->allowing_disk_regex != NULL) {
        flb_regex_destroy(ctx->allowing_disk_regex);
    }

    if (ctx->denying_disk_regex != NULL) {
        flb_regex_destroy(ctx->denying_disk_regex);
    }

    if (ctx->allowing_nic_regex != NULL) {
        flb_regex_destroy(ctx->allowing_nic_regex);
    }

    if (ctx->cmt) {
        cmt_destroy(ctx->cmt);
    }

    flb_free(ctx);
}
