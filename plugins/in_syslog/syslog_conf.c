/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_utils.h>

#include "syslog.h"
#include "syslog_unix.h"
#include "syslog_conf.h"

struct flb_syslog *syslog_conf_create(struct flb_input_instance *i_ins,
                                      struct flb_config *config)
{
    char *tmp;
    struct flb_syslog *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_syslog));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->evl = config->evl;
    ctx->i_ins = i_ins;
    mk_list_init(&ctx->connections);

    tmp = flb_input_get_property("path", i_ins);
    if (tmp) {
        ctx->unix_path = flb_strdup(tmp);
    }

    /* Chunk size */
    tmp = flb_input_get_property("chunk_size", i_ins);
    if (!tmp) {
        ctx->chunk_size = FLB_SYSLOG_CHUNK; /* 32KB */
    }
    else {
        /* Convert KB unit to Bytes */
        ctx->chunk_size  = flb_utils_size_to_bytes(tmp);
    }

    /* Buffer size */
    tmp = flb_input_get_property("buffer_size", i_ins);
    if (!tmp) {
        ctx->buffer_size = ctx->chunk_size;
    }
    else {
        /* Convert KB unit to Bytes */
        ctx->buffer_size  = flb_utils_size_to_bytes(tmp);
    }

    tmp = flb_input_get_property("parser", i_ins);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
    }
    else {
        ctx->parser = flb_parser_get("syslog", config);
    }

    if (!ctx->parser) {
        flb_error("[in_syslog] parser not set");
        syslog_conf_destroy(ctx);
        return NULL;
    }

    return ctx;
}

int syslog_conf_destroy(struct flb_syslog *ctx)
{
    syslog_unix_destroy(ctx);
    flb_free(ctx);

    return 0;
}
