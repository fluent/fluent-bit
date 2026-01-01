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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_utils.h>

#include "syslog.h"
#include "syslog_server.h"
#include "syslog_conf.h"

struct flb_syslog *syslog_conf_create(struct flb_input_instance *ins,
                                      struct flb_config *config)
{
    int ret;
    char port[16];
    struct flb_syslog *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_syslog));

    if (ctx == NULL) {
        flb_errno();

        return NULL;
    }

    ctx->ins = ins;

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(ins, "could not initialize event encoder");
        syslog_conf_destroy(ctx);

        return NULL;
    }

    mk_list_init(&ctx->connections);

    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_log_event_encoder_destroy(ctx->log_encoder);

        flb_plg_error(ins, "unable to load configuration");
        flb_free(ctx);

        return NULL;
    }

    /* Syslog mode: unix_udp, unix_tcp, tcp or udp */
    if (ctx->mode_str) {
#ifdef FLB_SYSTEM_WINDOWS
        if (strcasestr(ctx->mode_str, "unix") != NULL) {
            flb_log_event_encoder_destroy(ctx->log_encoder);

            flb_plg_error(ins, "unix sockets are note available in windows");
            flb_free(ctx);

            return NULL;
        }

#undef FLB_SYSLOG_UNIX_UDP
#define FLB_SYSLOG_UNIX_UDP FLB_SYSLOG_UDP
#endif
        if (strcasecmp(ctx->mode_str, "unix_tcp") == 0) {
            ctx->mode = FLB_SYSLOG_UNIX_TCP;
        }
        else if (strcasecmp(ctx->mode_str, "unix_udp") == 0) {
            ctx->mode = FLB_SYSLOG_UNIX_UDP;
        }
        else if (strcasecmp(ctx->mode_str, "tcp") == 0) {
            ctx->mode = FLB_SYSLOG_TCP;
        }
        else if (strcasecmp(ctx->mode_str, "udp") == 0) {
            ctx->mode = FLB_SYSLOG_UDP;
        }
        else {
            flb_log_event_encoder_destroy(ctx->log_encoder);

            flb_error("[in_syslog] Unknown syslog mode %s", ctx->mode_str);
            flb_free(ctx);
            return NULL;
        }
    }
    else {
        ctx->mode = FLB_SYSLOG_UNIX_UDP;
    }

    /* TCP Frame type (only applies to stream modes; default newline) */
    ctx->frame_type = FLB_SYSLOG_FRAME_NEWLINE;
    if (ctx->format_str != NULL) {
        if (strcasecmp(ctx->format_str, "octet_counting") == 0 ||
            strcasecmp(ctx->format_str, "octet") == 0) {
            ctx->frame_type = FLB_SYSLOG_FRAME_OCTET_COUNTING;
        }
        else if (strcasecmp(ctx->format_str, "newline") != 0) {
            flb_plg_warn(ins, "[in_syslog] unknown frame '%s', using 'newline'",
                         ctx->format_str);
        }
    }

    /* Check if TCP mode was requested */
    if (ctx->mode == FLB_SYSLOG_TCP || ctx->mode == FLB_SYSLOG_UDP) {
        /* Listen interface (if not set, defaults to 0.0.0.0:5140) */
        flb_input_net_default_listener("0.0.0.0", 5140, ins);
        ctx->listen = ins->host.listen;
        snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
        ctx->port = flb_strdup(port);
    }

    /* Unix socket path and permission */
    if (ctx->mode == FLB_SYSLOG_UNIX_UDP || ctx->mode == FLB_SYSLOG_UNIX_TCP) {
        if (ctx->unix_perm_str) {
            ctx->unix_perm = strtol(ctx->unix_perm_str, NULL, 8) & 07777;
        } else {
            ctx->unix_perm = 0644;
        }
    }

    /* Buffer Chunk Size */
    if (ctx->buffer_chunk_size == -1) {
        flb_log_event_encoder_destroy(ctx->log_encoder);

        flb_plg_error(ins, "invalid buffer_chunk_size");
        flb_free(ctx);
        return NULL; 
    }

    /* Buffer Max Size */
    if (ctx->buffer_max_size == -1) {
        flb_log_event_encoder_destroy(ctx->log_encoder);

        flb_plg_error(ins, "invalid buffer_max_size");
        flb_free(ctx);
        return NULL;
    }
    else if (ctx->buffer_max_size == 0) {
        ctx->buffer_max_size = ctx->buffer_chunk_size;
    }

    /* Socket rcv buffer size */
    if (ctx->receive_buffer_size == -1 || ctx->receive_buffer_size>INT_MAX) {
        flb_log_event_encoder_destroy(ctx->log_encoder);

        flb_plg_error(ins, "invalid receive_buffer_size");
        flb_free(ctx);
        return NULL;
    }

    /* Parser */
    if (ctx->parser_name) {
        ctx->parser = flb_parser_get(ctx->parser_name, config);
    }
    else {
        if (ctx->mode == FLB_SYSLOG_TCP || ctx->mode == FLB_SYSLOG_UDP) {
            ctx->parser = flb_parser_get("syslog-rfc5424", config);
        }
        else {
            ctx->parser = flb_parser_get("syslog-rfc3164-local", config);
        }
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
    if (ctx->log_encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    syslog_server_destroy(ctx);

    flb_free(ctx);

    return 0;
}
