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

//#include <fluent-bit/flb_input_thread.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_input.h>

#include "http2.h"
#include "http2_config.h"

struct flb_http2 *http2_config_create(struct flb_input_instance *ins)
{
    struct mk_list            *header_iterator;
    struct flb_slist_entry    *header_value;
    struct flb_slist_entry    *header_name;
    struct flb_config_map_val *header_pair;
    char                       port[8];
    int                        ret;
    struct flb_http2           *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_http2));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:9880) */
    flb_input_net_default_listener("0.0.0.0", 9880, ins);

    ctx->listen = flb_strdup(ins->host.listen);
    snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
    ctx->tcp_port = flb_strdup(port);

    /* monkey detects server->workers == 0 as the server not being initialized at the
     * moment so we want to make sure that it stays that way!
     */

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);

        http2_config_destroy(ctx);

        return NULL;
    }

    ctx->success_headers_str = flb_sds_create_size(1);

    if (ctx->success_headers_str == NULL) {
        http2_config_destroy(ctx);

        return NULL;
    }

    flb_config_map_foreach(header_iterator, header_pair, ctx->success_headers) {
        header_name = mk_list_entry_first(header_pair->val.list,
                                          struct flb_slist_entry,
                                          _head);

        header_value = mk_list_entry_last(header_pair->val.list,
                                          struct flb_slist_entry,
                                          _head);

        ret = flb_sds_cat_safe(&ctx->success_headers_str,
                               header_name->str,
                               flb_sds_len(header_name->str));

        if (ret == 0) {
            ret = flb_sds_cat_safe(&ctx->success_headers_str,
                                   ": ",
                                   2);
        }

        if (ret == 0) {
            ret = flb_sds_cat_safe(&ctx->success_headers_str,
                                   header_value->str,
                                   flb_sds_len(header_value->str));
        }

        if (ret == 0) {
            ret = flb_sds_cat_safe(&ctx->success_headers_str,
                                   "\r\n",
                                   2);
        }

        if (ret != 0) {
            http2_config_destroy(ctx);

            return NULL;
        }
    }

    ret = flb_http_server_init(&ctx->http_server, 
                                HTTP_PROTOCOL_AUTODETECT,
                                0,
                                NULL,
                                ctx->listen,
                                ins->host.port,
                                ins->tls,
                                ins->flags,
                                &ins->net_setup,
                                flb_input_get_event_loop(ins),
                                ins->config,
                                (void *) ctx);

    if (ret != 0) {
        http2_config_destroy(ctx);

        return NULL;
    }

    return ctx;
}

int http2_config_destroy(struct flb_http2 *ctx)
{
    flb_http_server_destroy(&ctx->http_server);

    flb_log_event_encoder_destroy(&ctx->log_encoder);

    if (ctx->success_headers_str != NULL) {
        flb_sds_destroy(ctx->success_headers_str);
    }

    flb_sds_destroy(ctx->listen);
    flb_sds_destroy(ctx->tcp_port);

    flb_free(ctx);

    return 0;
}
