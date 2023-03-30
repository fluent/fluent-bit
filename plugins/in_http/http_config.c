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

#include <fluent-bit/flb_input_plugin.h>

#include "http.h"
#include "http_conn.h"

struct flb_http *http_config_create(struct flb_input_instance *ins)
{
    int ret;
    char port[8];
    struct flb_http *ctx;
    struct flb_config_map_val *mv = NULL;
    struct mk_list *head = NULL;
    struct header_key_condition *header_cond = NULL;

    ctx = flb_calloc(1, sizeof(struct flb_http));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->connections);
    mk_list_init(&ctx->add_headers);

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

    /* HTTP Server specifics */
    ctx->server = flb_calloc(1, sizeof(struct mk_server));
    ctx->server->keep_alive = MK_TRUE;

    /* monkey detects server->workers == 0 as the server not being initialized at the
     * moment so we want to make sure that it stays that way!
     */

    /* 'add_request_header' configuration */
    ctx->add_headers_num = 0;
    flb_config_map_foreach(head, mv, ctx->add_headers_map) {
        header_cond = flb_malloc(sizeof(struct header_key_condition));
        if (header_cond == NULL) {
            flb_errno();
            continue;
        }

        header_cond->regex = flb_regex_create(mv->val.str);
        if (header_cond->regex == NULL) {
            flb_free(header_cond);
            flb_plg_error(ctx->ins, "invalid regex=%s", mv->val.str);
            continue;
        }

        mk_list_add(&header_cond->_head, &ctx->add_headers);
        ctx->add_headers_num++;
    }

    return ctx;
}

int http_config_destroy(struct flb_http *ctx)
{
    struct mk_list *tmp = NULL;
    struct mk_list *head = NULL;
    struct header_key_condition *cond = NULL;

    /* release all connections */
    http_conn_release_all(ctx);

    if (ctx->collector_id != -1) {
        flb_input_collector_delete(ctx->collector_id, ctx->ins);

        ctx->collector_id = -1;
    }

    if (ctx->downstream != NULL) {
        flb_downstream_destroy(ctx->downstream);
    }

    mk_list_foreach_safe(head, tmp, &ctx->add_headers) {
        cond = mk_list_entry(head, struct header_key_condition, _head);
        flb_regex_destroy(cond->regex);
        flb_free(cond);
    }

    if (ctx->server) {
        flb_free(ctx->server);
    }
    flb_free(ctx->listen);
    flb_free(ctx->tcp_port);
    flb_free(ctx);
    return 0;
}
