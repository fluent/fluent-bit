/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_kv.h>

#include "syslog_conf.h"

struct flb_syslog *flb_syslog_config_create(struct flb_output_instance *ins,
                                            struct flb_config *config)
{
    int ret;
    const char *tmp;
    struct flb_syslog *ctx = NULL;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_syslog));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->parsed_mode = FLB_SYSLOG_UDP;
    ctx->parsed_format = FLB_SYSLOG_RFC5424;
    ctx->maxsize = -1;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_syslog_config_destroy(ctx);
        return NULL;
    }

    /* Set context */
    flb_output_set_context(ins, ctx);

    /* Config Mode */
    tmp = flb_output_get_property("mode", ins);
    if (tmp) {
        if (!strcasecmp(tmp, "tcp")) {
            ctx->parsed_mode = FLB_SYSLOG_TCP;
        }
        else if (!strcasecmp(tmp, "tls")) {
            ctx->parsed_mode = FLB_SYSLOG_TLS;
        }
        else if (!strcasecmp(tmp, "udp")) {
            ctx->parsed_mode = FLB_SYSLOG_UDP;
        }
        else {
            flb_plg_error(ctx->ins, "unknown syslog mode %s", tmp);
            return NULL;
        }
    }

    /* syslog_format */
    tmp = flb_output_get_property("syslog_format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "rfc3164") == 0) {
            ctx->parsed_format = FLB_SYSLOG_RFC3164;
        }
        else if (strcasecmp(tmp, "rfc5424") == 0) {
            ctx->parsed_format = FLB_SYSLOG_RFC5424;
        }
        else {
            flb_plg_error(ctx->ins, "unknown syslog format %s", tmp);
            return NULL;
        }
    }

    /* syslog maxsize */
    if (ctx->maxsize < 0) {
        flb_plg_error(ctx->ins, "invalid 'syslog_maxsize' value %i",
                      ctx->maxsize);
        return NULL;
    }

    return ctx;
}

void flb_syslog_config_destroy(struct flb_syslog *ctx)
{
    flb_free(ctx);
}
