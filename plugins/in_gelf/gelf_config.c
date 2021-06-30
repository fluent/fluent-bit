/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_unescape.h>

#include "gelf.h"
#include "gelf_conn.h"
#include "gelf_config.h"

#include <stdlib.h>

struct flb_in_gelf_config *gelf_config_init(struct flb_input_instance *ins)
{
    char port[16];
    const char *buffer_size;
    const char *chunk_size;
    const char *mode;
    struct flb_in_gelf_config *ctx;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_in_gelf_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* mode: tcp or udp */
    ctx->mode = FLB_GELF_TCP;
    mode = flb_input_get_property("mode", ins);
    if (mode) {
        if (strcasecmp(mode, "tcp") == 0) {
            ctx->mode = FLB_GELF_TCP;
        }
        else if (strcasecmp(mode, "udp") == 0) {
            ctx->mode = FLB_GELF_UDP;
            flb_error("[in_gelf] gelf mode %s not implemented yet", mode);
            flb_free(ctx);
            return NULL;
        }
        else {
            flb_error("[in_gelf] Unknown gelf mode %s", mode);
            flb_free(ctx);
            return NULL;
        }
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:12201) */
    flb_input_net_default_listener("0.0.0.0", 12201, ins);
    ctx->listen = ins->host.listen;
    snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
    ctx->port = flb_strdup(port);

    /* Chunk size */
    chunk_size = flb_input_get_property("chunk_size", ins);
    if (!chunk_size) {
        ctx->chunk_size = FLB_IN_GELF_CHUNK; /* 32KB */
    }
    else {
        /* Convert KB unit to Bytes */
        ctx->chunk_size  = (atoi(chunk_size) * 1024);
    }

    /* Buffer size */
    buffer_size = flb_input_get_property("buffer_size", ins);
    if (!buffer_size) {
        ctx->buffer_size = ctx->chunk_size;
    }
    else {
        /* Convert KB unit to Bytes */
        ctx->buffer_size  = (atoi(buffer_size) * 1024);
    }

    return ctx;
}

int gelf_config_destroy(struct flb_in_gelf_config *ctx)
{
    flb_free(ctx->port);
    flb_free(ctx);

    return 0;
}
