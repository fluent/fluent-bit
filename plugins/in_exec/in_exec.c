/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>

#include "in_exec.h"

int cb_exec_collect(struct flb_config *config, void *in_context);

int cb_exec_init(struct flb_config *config)
{
    return 0;
}

int cb_exec_pre_run(void *in_context, struct flb_config *config)
{
    int ret;
    struct flb_in_exec_config *ctx;

    if (!config->file) {
        flb_utils_error_c("EXEC input requires a configuration file");
    }

    ctx = exec_config_init(config->file);
    if (!ctx) {
        flb_debug("EXEC input can't find EXEC configuration");
        return -1;
    }

    ctx->data_idx = 0;
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    ret = flb_input_set_context("exec", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for exec input plugin");
    }

    ret = flb_input_set_collector_time("exec",
                                      cb_exec_collect,
                                      ctx->run_interval,
                                      0,
                                      config);
    if (ret == -1) {
        flb_utils_error_c("[in_exec] Could not set collector");
    }


    /* nothing to do */
    return 0;
}

int cb_exec_collect(struct flb_config *config, void *in_context)
{
    FILE *fp;
    (void)config;
    struct flb_in_exec_config *ctx = in_context;
    char buf[DATA_SIZE];

    fp = popen(ctx->command, "r");
    if ((fp = popen(ctx->command, "r")) == NULL) {
        flb_utils_error_c("Could not execute command in in_exec");
    }

    /* XXX: limited to DATA_SIZE (64KB) */
    (void)fread(buf, sizeof(char), DATA_SIZE, fp);
    (void)pclose(fp);

    msgpack_pack_map(&ctx->mp_pck, 2);
    msgpack_pack_raw(&ctx->mp_pck, 4);
    msgpack_pack_raw_body(&ctx->mp_pck, "time", 4);
    msgpack_pack_uint64(&ctx->mp_pck, time(NULL));
    msgpack_pack_raw(&ctx->mp_pck, 7);
    msgpack_pack_raw_body(&ctx->mp_pck, "command", 7);
    msgpack_pack_raw(&ctx->mp_pck, strlen(buf));
    msgpack_pack_raw_body(&ctx->mp_pck, buf, strlen(buf));

    flb_debug("[in_exec] command total %d, current data size = %zd",
              ctx->data_idx,
              strlen(buf));

    ++ctx->data_idx;
    return 0;

}

void *cb_exec_flush(void *in_context, int *size)
{
    char *buf;
    struct flb_in_exec_config *ctx = in_context;

    buf = malloc(ctx->mp_sbuf.size);
    if (!buf) {
        flb_debug("[in_exec] %s can't allocate enough buffer (size=%zd)",
                  ctx->mp_sbuf.size);
        return NULL;
    }

    memcpy(buf, ctx->mp_sbuf.data, ctx->mp_sbuf.size);
    *size = ctx->mp_sbuf.size;
    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);
    ctx->data_idx = 0;

    return buf;
}


struct flb_input_plugin in_exec_plugin = {
    .name         = "exec",
    .description  = "Execute command",
    .cb_init      = cb_exec_init,
    .cb_pre_run   = cb_exec_pre_run,
    .cb_collect   = cb_exec_collect,
    .cb_flush_buf = cb_exec_flush
};
