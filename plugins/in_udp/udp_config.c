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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_unescape.h>

#include "udp.h"
#include "udp_conn.h"
#include "udp_config.h"

#include <stdlib.h>

struct flb_in_udp_config *udp_config_init(struct flb_input_instance *ins)
{
    int ret;
    int len;
    char port[16];
    char *out;
    struct flb_in_udp_config *ctx;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_in_udp_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->format = FLB_UDP_FMT_JSON;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        flb_free(ctx);
        return NULL;
    }

    /* Data format (expected payload) */
    if (ctx->format_name) {
        if (strcasecmp(ctx->format_name, "json") == 0) {
            ctx->format = FLB_UDP_FMT_JSON;
        }
        else if (strcasecmp(ctx->format_name, "none") == 0) {
            ctx->format = FLB_UDP_FMT_NONE;
        }
        else {
            flb_plg_error(ctx->ins, "unrecognized format value '%s'", ctx->format_name);
            flb_free(ctx);
            return NULL;
        }
    }

    /* String separator used to split records when using 'format none' */
    if (ctx->raw_separator) {
        len = strlen(ctx->raw_separator);
        out = flb_malloc(len + 1);
        if (!out) {
            flb_errno();
            flb_free(ctx);
            return NULL;
        }
        ret = flb_unescape_string(ctx->raw_separator, len, &out);
        if (ret <= 0) {
            flb_plg_error(ctx->ins, "invalid separator");
            flb_free(out);
            flb_free(ctx);
            return NULL;
        }

        ctx->separator = flb_sds_create_len(out, ret);
        if (!ctx->separator) {
            flb_free(out);
            flb_free(ctx);
            return NULL;
        }
        flb_free(out);
    }
    if (!ctx->separator) {
        ctx->separator = flb_sds_create_len("\n", 1);
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:5170) */
    flb_input_net_default_listener("0.0.0.0", 5170, ins);
    ctx->listen = ins->host.listen;
    snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
    ctx->port = flb_strdup(port);

    /* Chunk size */
    if (ctx->chunk_size_str) {
        /* Convert KB unit to Bytes */
        ctx->chunk_size  = (atoi(ctx->chunk_size_str) * 1024);
    } else {
        ctx->chunk_size  = atoi(FLB_IN_UDP_CHUNK);
    }

    /* Buffer size */
    if (!ctx->buffer_size_str) {
        ctx->buffer_size = ctx->chunk_size;
    }
    else {
        /* Convert KB unit to Bytes */
        ctx->buffer_size  = (atoi(ctx->buffer_size_str) * 1024);
    }

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(ctx->ins, "could not initialize event encoder");
        udp_config_destroy(ctx);

        ctx = NULL;
    }

    return ctx;
}

int udp_config_destroy(struct flb_in_udp_config *ctx)
{
    if (ctx->log_encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    if (ctx->collector_id != -1) {
        flb_input_collector_delete(ctx->collector_id, ctx->ins);

        ctx->collector_id = -1;
    }

    if (ctx->downstream != NULL) {
        flb_downstream_destroy(ctx->downstream);
    }

    flb_sds_destroy(ctx->separator);
    flb_free(ctx->port);
    flb_free(ctx);

    return 0;
}
