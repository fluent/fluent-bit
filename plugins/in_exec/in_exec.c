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
    uint64_t val;
    size_t str_len = 0;
    FILE *cmdp = NULL;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_exec *ctx = in_context;

    /* variables for parser */
    int parser_ret = -1;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;

    if (ctx->oneshot == FLB_TRUE) {
        ret = flb_pipe_r(ctx->ch_manager[0], &val, sizeof(val));
        if (ret == -1) {
            flb_errno();
            return -1;
        }
    }

    cmdp = popen(ctx->cmd, "r");
    if (cmdp == NULL) {
        flb_plg_debug(ctx->ins, "command %s failed", ctx->cmd);
        goto collect_end;
    }

    if (ctx->parser) {
        while (fgets(ctx->buf, ctx->buf_size, cmdp) != NULL) {
            str_len = strnlen(ctx->buf, ctx->buf_size);
            if (ctx->buf[str_len - 1] == '\n') {
                ctx->buf[--str_len] = '\0'; /* chomp */
            }

            flb_time_get(&out_time);
            parser_ret = flb_parser_do(ctx->parser, ctx->buf, str_len,
                                       &out_buf, &out_size, &out_time);
            if (parser_ret >= 0) {
                if (flb_time_to_nanosec(&out_time) == 0L) {
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
        }
    }
    else {
        while (fgets(ctx->buf, ctx->buf_size, cmdp) != NULL) {
            str_len = strnlen(ctx->buf, ctx->buf_size);
            if (ctx->buf[str_len - 1] == '\n') {
                ctx->buf[--str_len] = '\0'; /* chomp */
            }

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
                               struct flb_config *config
)
{
    int ret;

    ctx->ins = in;

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(in, "unable to load configuration");
        return -1;
    }
   
    /* filepath setting */
    if (ctx->cmd == NULL) {
        flb_plg_error(in, "no input 'command' was given");
        return -1;
    }

    if (ctx->parser_name != NULL) {
        ctx->parser = flb_parser_get(ctx->parser_name, config);
        if (ctx->parser == NULL) {
            flb_plg_error(in, "requested parser '%s' not found", ctx->parser_name);
        }
    }

    if (ctx->buf_size == -1) {
        flb_plg_error(in, "buffer size is invalid");
        return -1;
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
    }

    if (ctx->oneshot) {
        ctx->interval_sec = -1;
        ctx->interval_nsec = -1;
    }

    flb_plg_debug(in, "interval_sec=%d interval_nsec=%d oneshot=%i buf_size=%d",
              ctx->interval_sec, ctx->interval_nsec, ctx->oneshot, ctx->buf_size);

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

    if (ctx->ch_manager[0] > -1) {
        flb_pipe_close(ctx->ch_manager[0]);
    }

    if (ctx->ch_manager[1] > -1) {
        flb_pipe_close(ctx->ch_manager[1]);
    }

    flb_free(ctx);
}

/* Initialize plugin */
static int in_exec_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    struct flb_exec *ctx = NULL;
    int ret = -1;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_exec));
    if (!ctx) {
        return -1;
    }
    ctx->parser = NULL;

    /* Initialize exec config */
    ret = in_exec_config_read(ctx, in, config);
    if (ret < 0) {
        goto init_error;
    }

    ctx->buf = flb_malloc(ctx->buf_size);
    if (ctx->buf == NULL) {
        flb_plg_error(in, "could not allocate exec buffer");
        goto init_error;
    }

    flb_input_set_context(in, ctx);

    ctx->ch_manager[0] = -1;
    ctx->ch_manager[1] = -1;

    if (ctx->oneshot == FLB_TRUE) {
        if (flb_pipe_create(ctx->ch_manager)) {
            flb_plg_error(in, "could not create pipe for oneshot command");
            goto init_error;
        }

        ret = flb_input_set_collector_event(in,
                                            in_exec_collect,
                                            ctx->ch_manager[0], config);
    }
    else {
        ret = flb_input_set_collector_time(in,
                                           in_exec_collect,
                                           ctx->interval_sec,
                                           ctx->interval_nsec, config);
    }
    if (ret < 0) {
        flb_plg_error(in, "could not set collector for exec input plugin");
        goto init_error;
    }

    return 0;

  init_error:
    delete_exec_config(ctx);

    return -1;
}

static int in_exec_prerun(struct flb_input_instance *ins,
                          struct flb_config *config, void *in_context)
{
    int ret;
    uint64_t val = 0xc003;  /* dummy constant */
    struct flb_exec *ctx = in_context;
    (void) ins;
    (void) config;

    if (ctx->oneshot == FLB_FALSE) {
        return 0;
    }

    /* Kick the oneshot execution */
    ret = flb_pipe_w(ctx->ch_manager[1], &val, sizeof(val));
    if (ret == -1) {
        flb_errno();
        return -1;
    }
    return 0;
}

static int in_exec_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_exec *ctx = data;

    delete_exec_config(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "command", NULL,
     0, FLB_TRUE, offsetof(struct flb_exec, cmd),
     "Set the command to execute"
    },
    {
     FLB_CONFIG_MAP_STR, "parser", NULL,
     0, FLB_TRUE, offsetof(struct flb_exec, parser_name),
     "Set a parser"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_exec, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_exec, interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
    {
      FLB_CONFIG_MAP_SIZE, "buf_size", DEFAULT_BUF_SIZE,
      0, FLB_TRUE, offsetof(struct flb_exec, buf_size),
      "Set the buffer size"
    },
    {
      FLB_CONFIG_MAP_BOOL, "oneshot", "false",
      0, FLB_TRUE, offsetof(struct flb_exec, oneshot),
      "execute the command only once"
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_exec_plugin = {
    .name         = "exec",
    .description  = "Exec Input",
    .cb_init      = in_exec_init,
    .cb_pre_run   = in_exec_prerun,
    .cb_collect   = in_exec_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_exec_exit,
    .config_map   = config_map
};
