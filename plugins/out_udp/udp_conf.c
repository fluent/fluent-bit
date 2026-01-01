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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>

#include "udp.h"
#include "udp_conf.h"

struct flb_out_udp *flb_udp_conf_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    const char *tmp;
    struct flb_out_udp *ctx = NULL;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_udp));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Set default network configuration if not set */
    flb_output_net_default("127.0.0.1", 5170, ins);

    /* raw message key mode */
    if (ctx->raw_message_key) {
        ctx->ra_raw_message_key = flb_ra_create(ctx->raw_message_key, FLB_TRUE);
        if (!ctx->ra_raw_message_key) {
            flb_plg_error(ctx->ins, "could not create record accessor for raw_message_key");
            flb_free(ctx);
            return NULL;
        }
    }

    /* Output format */
    ctx->out_format = FLB_PACK_JSON_FORMAT_NONE;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "unrecognized 'format' option '%s'. "
                          "Using 'msgpack'", tmp);
        }
        else {
            ctx->out_format = ret;
        }
    }

    /* Date key */
    ctx->date_key = ctx->json_date_key;
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        /* Just check if we have to disable it */
        if (flb_utils_bool(tmp) == FLB_FALSE) {
            ctx->date_key = NULL;
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "unrecognized 'json_date_format' option '%s'. "
                          "Using 'double'", tmp);
        }
        else {
            ctx->json_date_format = ret;
        }
    }

    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    ctx->endpoint_descriptor = flb_net_udp_connect(ins->host.name,
                                                   ins->host.port,
                                                   ins->net_setup.source_address);

    if (ctx->endpoint_descriptor < 0) {
        flb_udp_conf_destroy(ctx);

        flb_plg_error(ctx->ins, "Error creating upstream socket");

        ctx = NULL;
    }

    return ctx;
}

void flb_udp_conf_destroy(struct flb_out_udp *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->ra_raw_message_key) {
        flb_ra_destroy(ctx->ra_raw_message_key);
    }

    if (ctx->endpoint_descriptor >= 0) {
        flb_socket_close(ctx->endpoint_descriptor);
    }

    flb_free(ctx);

    ctx = NULL;
}
