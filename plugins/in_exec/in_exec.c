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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "in_exec.h"

/* cb_collect callback */
static int in_exec_collect(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    int ret = -1;
    size_t str_len = 0;
    FILE *cmdp = NULL;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_exec *ctx = in_context;

    char *read_result = NULL;
    char *buf_cur = ctx->buf;
    size_t buf_free = ctx->buf_size;
    size_t buf_read = 0;
    int buffer_has_data = 0;

    /* variables for parser */
    int parser_ret = -1;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;

    cmdp = popen(ctx->cmd, "r");
    if (cmdp == NULL) {
        flb_plg_debug(ctx->ins, "command %s failed", ctx->cmd);
        goto collect_end;
    }

    while ((read_result = fgets(buf_cur, buf_free, cmdp)) != NULL
            || buffer_has_data) {
        if (read_result != NULL) {
            buf_read = strnlen(buf_cur, buf_free);
            str_len += buf_read;
            buf_free -= buf_read;
            /* if multiline logs are enabled, continue until EOF or full buffer */
            if (ctx->multiline && buf_free > 1) {
                buffer_has_data = 1;
                buf_cur += buf_read;
                continue;
            }
        }
        /* strip newline where applicable */
        if (!ctx->multiline && ctx->buf[str_len - 1] == '\n') {
            ctx->buf[str_len - 1] = '\0'; /* chomp */
            str_len -= 1;
        }
        buf_cur = ctx->buf;
        buf_free = ctx->buf_size;
        buf_read = 0;

        if (ctx->parser) {
            flb_time_get(&out_time);
            parser_ret = flb_parser_do(ctx->parser, ctx->buf, str_len,
                                       &out_buf, &out_size, &out_time);
            if (parser_ret >= 0) {
                if (flb_time_to_double(&out_time) == 0.0) {
                    flb_time_get(&out_time);
                }

                /* Initialize local msgpack buffer */
                msgpack_sbuffer_init(&mp_sbuf);
                msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

                msgpack_pack_array(&mp_pck, 2);
                flb_time_append_to_msgpack(&out_time, &mp_pck, 0);
                msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);

                flb_input_chunk_append_raw(ins, NULL, 0,
                                           mp_sbuf.data, mp_sbuf.size);
                msgpack_sbuffer_destroy(&mp_sbuf);
                flb_free(out_buf);
            }
            else {
                flb_plg_trace(ctx->ins, "tried to parse '%s'", ctx->buf);
                flb_plg_trace(ctx->ins, "buf_size %zu", ctx->buf_size);
                flb_plg_error(ctx->ins, "parser returned an error");
            }
            buffer_has_data = 0;
            str_len = 0;
        }
        else {
            /* Initialize local msgpack buffer */
            msgpack_sbuffer_init(&mp_sbuf);
            msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

            msgpack_pack_array(&mp_pck, 2);
            flb_pack_time_now(&mp_pck);
            msgpack_pack_map(&mp_pck, 1);

            msgpack_pack_str(&mp_pck, 4);
            msgpack_pack_str_body(&mp_pck, "exec", 4);
            msgpack_pack_str(&mp_pck, str_len);
            msgpack_pack_str_body(&mp_pck,
                                ctx->buf, str_len);

            flb_input_chunk_append_raw(ins, NULL, 0,
                                       mp_sbuf.data, mp_sbuf.size);
            msgpack_sbuffer_destroy(&mp_sbuf);

            buffer_has_data = 0;
            str_len = 0;
        }
    }

    ret = 0; /* success */

 collect_end:
    if(cmdp != NULL){
        pclose(cmdp);
    }

    return ret;
}

/* read config file and*/
static int in_exec_config_read(struct flb_exec *ctx,
                               struct flb_input_instance *in,
                               struct flb_config *config,
                               int *interval_sec,
                               int *interval_nsec
)
{
    const char *cmd = NULL;
    const char *pval = NULL;

    ctx->ins = in;

    /* filepath setting */
    cmd = flb_input_get_property("command", in);
    if (cmd == NULL) {
        flb_error("[in_exec] no input 'command' was given");
        return -1;
    }
    ctx->cmd = cmd;

    pval = flb_input_get_property("parser", in);
    if (pval != NULL) {
        ctx->parser = flb_parser_get(pval, config);
        if (ctx->parser == NULL) {
            flb_error("[in_exec] requested parser '%s' not found", pval);
        }
    }

    pval = flb_input_get_property("buf_size", in);
    if (pval != NULL) {
        ctx->buf_size = (size_t) flb_utils_size_to_bytes(pval);

        if (ctx->buf_size == -1) {
            flb_error("[in_exec] buffer size '%s' is invalid", pval);
            return -1;
        }
    }
    else {
        ctx->buf_size = DEFAULT_BUF_SIZE;
    }

    pval = flb_input_get_property("multiline", in);
    if (pval != NULL && flb_utils_bool(pval)) {
        ctx->multiline = FLB_TRUE;
    }
    else {
        ctx->multiline = FLB_FALSE;
    }

    /* interval settings */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        *interval_sec = atoi(pval);
    }
    else {
        *interval_sec = DEFAULT_INTERVAL_SEC;
    }

    pval = flb_input_get_property("interval_nsec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        *interval_nsec = atoi(pval);
    }
    else {
        *interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    if (*interval_sec <= 0 && *interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        *interval_sec = DEFAULT_INTERVAL_SEC;
        *interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    flb_debug("[in_exec] interval_sec=%d interval_nsec=%d",
              *interval_sec, *interval_nsec);

    return 0;
}

static void delete_exec_config(struct flb_exec *ctx)
{
    if (!ctx) {
        return;
    }

    /* release buffer */
    if (ctx->buf != NULL) {
        flb_free(ctx->buf);
    }
    flb_free(ctx);
}

/* Initialize plugin */
static int in_exec_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    struct flb_exec *ctx = NULL;
    int ret = -1;
    int interval_sec = 0;
    int interval_nsec = 0;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_exec));
    if (!ctx) {
        return -1;
    }
    ctx->parser = NULL;

    /* Initialize exec config */
    ret = in_exec_config_read(ctx, in, config, &interval_sec, &interval_nsec);
    if (ret < 0) {
        goto init_error;
    }

    ctx->buf = flb_malloc(ctx->buf_size);
    if (ctx->buf == NULL) {
        flb_error("could not allocate exec buffer");
        goto init_error;
    }

    flb_input_set_context(in, ctx);

    ret = flb_input_set_collector_time(in,
                                       in_exec_collect,
                                       interval_sec,
                                       interval_nsec, config);
    if (ret < 0) {
        flb_error("could not set collector for exec input plugin");
        goto init_error;
    }

    return 0;

  init_error:
    delete_exec_config(ctx);

    return -1;
}

static int in_exec_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_exec *ctx = data;

    delete_exec_config(ctx);
    return 0;
}


struct flb_input_plugin in_exec_plugin = {
    .name         = "exec",
    .description  = "Exec Input",
    .cb_init      = in_exec_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_exec_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_exec_exit
};
