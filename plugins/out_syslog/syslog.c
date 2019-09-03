/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "syslog.h"
#include "syslog_conf.h"

static int cb_syslog_init(struct flb_output_instance *ins,
                       struct flb_config *config, void *data)
{
    struct flb_out_syslog *ctx = NULL;
    (void) data;

    ctx = flb_syslog_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_syslog_flush(const void *data, size_t bytes,
                         const char *tag, int tag_len,
                         struct flb_input_instance *i_ins,
                         void *out_context,
                         struct flb_config *config)
{
    int ret = FLB_ERROR;
    struct flb_out_syslog *ctx = out_context;
    size_t bytes_sent;
    flb_sds_t json = NULL;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    (void) i_ins;
    int len = -1;

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_error("[out_syslog] no upstream connections available to %s:%i",
                  u->tcp_host, u->tcp_port);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

	/*syslog will need json format in any cases*/
    json = flb_pack_msgpack_to_json_format(data, bytes,
                                           ctx->out_format,
                                           ctx->json_date_format,
                                           ctx->json_date_key);
    if (!json) {
        flb_error("[out_syslog] error formatting JSON payload");
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
	
	len = flb_out_syslog_render_message(ctx, json);
	if (len == -1) {
		flb_errno();
		flb_upstream_conn_release(u_conn);
		FLB_OUTPUT_RETURN(FLB_OK);
	}



	//flb_info("[wang test] this is rendered outMessage => '%s'", ctx->rMessage);
	
	ret = flb_io_net_write(u_conn, ctx->rMessage, len, &bytes_sent);
	
    flb_sds_destroy(json);
	

    if (ret == -1) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_syslog_exit(void *data, struct flb_config *config)
{
    struct flb_out_syslog *ctx = data;
    flb_syslog_conf_destroy(ctx);
    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_syslog_plugin = {
    .name           = "syslog",
    .description    = "SYSLOG Output",
    .cb_init        = cb_syslog_init,
    .cb_flush       = cb_syslog_flush,
    .cb_exit        = cb_syslog_exit,
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
