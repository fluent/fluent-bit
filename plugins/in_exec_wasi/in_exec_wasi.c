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
#include <fluent-bit/flb_kv.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef FLB_SYSTEM_WINDOWS
#define STDIN_FILENO (_fileno( stdin ))
#define STDOUT_FILENO (_fileno( stdout ))
#define STDERR_FILENO (_fileno( stderr ))
#else
#include <unistd.h>
#endif

#include "in_exec_wasi.h"

/* cb_collect callback */
static int in_exec_wasi_collect(struct flb_input_instance *ins,
                                struct flb_config *config, void *in_context)
{
    int ret = -1;
    uint64_t val;
    size_t str_len = 0;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_exec_wasi *ctx = in_context;
    struct flb_wasm *wasm = NULL;
    FILE *stdoutp = tmpfile();

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

    wasm = flb_wasm_instantiate(config, ctx->wasi_path, ctx->accessible_dir_list, -1, fileno(stdoutp), -1);
    if (wasm == NULL) {
        flb_plg_debug(ctx->ins, "instantiate wasm [%s] failed", ctx->wasi_path);
        goto collect_end;
    }
    ctx->wasm = wasm;

    ret = flb_wasm_call_wasi_main(ctx->wasm);

    if (ctx->parser) {
        rewind(stdoutp);

        while (fgets(ctx->buf, ctx->buf_size, stdoutp) != NULL) {
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

                ctx->ins->event_type = FLB_INPUT_LOGS;
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
        rewind(stdoutp);

        while (fgets(ctx->buf, ctx->buf_size, stdoutp) != NULL) {
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

            msgpack_pack_str(&mp_pck, 11);
            msgpack_pack_str_body(&mp_pck, "wasi_stdout", 11);
            msgpack_pack_str(&mp_pck, str_len);
            msgpack_pack_str_body(&mp_pck,
                                  ctx->buf, str_len);

            ctx->ins->event_type = FLB_INPUT_LOGS;
            flb_input_chunk_append_raw(ins, NULL, 0,
                                       mp_sbuf.data, mp_sbuf.size);
            msgpack_sbuffer_destroy(&mp_sbuf);
        }
    }

 collect_end:
    if (ctx->wasm != NULL) {
        flb_wasm_destroy(ctx->wasm);
    }
    fclose(stdoutp);

    return ret;
}

/* read config file and*/
static int in_exec_wasi_config_read(struct flb_exec_wasi *ctx,
                                    struct flb_input_instance *in,
                                    struct flb_config *config)
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
    if (ctx->wasi_path == NULL) {
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

static void delete_exec_wasi_config(struct flb_exec_wasi *ctx)
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
static int in_exec_wasi_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    struct flb_exec_wasi *ctx = NULL;
    int ret = -1;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_exec_wasi));
    if (!ctx) {
        return -1;
    }
    ctx->parser_name = NULL;

    /* Initialize exec config */
    ret = in_exec_wasi_config_read(ctx, in, config);
    if (ret < 0) {
        goto init_error;
    }

    flb_wasm_init(config);

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
                                            in_exec_wasi_collect,
                                            ctx->ch_manager[0], config);
    }
    else {
        ret = flb_input_set_collector_time(in,
                                           in_exec_wasi_collect,
                                           ctx->interval_sec,
                                           ctx->interval_nsec, config);
    }
    if (ret < 0) {
        flb_plg_error(in, "could not set collector for exec input plugin");
        goto init_error;
    }

    return 0;

  init_error:
    delete_exec_wasi_config(ctx);

    return -1;
}

static int in_exec_wasi_prerun(struct flb_input_instance *ins,
                          struct flb_config *config, void *in_context)
{
    int ret;
    uint64_t val = 0xc003;  /* dummy constant */
    struct flb_exec_wasi *ctx = in_context;
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

static int in_exec_wasi_exit(void *data, struct flb_config *config)
{
    struct flb_exec_wasi *ctx = data;

    flb_wasm_destroy_all(config);
    delete_exec_wasi_config(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "wasi_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_exec_wasi, wasi_path),
     "Set the path of WASM program to execute"
    },
    {
     FLB_CONFIG_MAP_CLIST, "accessible_paths", ".",
     0, FLB_TRUE, offsetof(struct flb_exec_wasi, accessible_dir_list),
     "Specifying paths to be accessible from a WASM program."
     "Default value is current working directory"
    },
    {
     FLB_CONFIG_MAP_STR, "parser", NULL,
     0, FLB_TRUE, offsetof(struct flb_exec_wasi, parser_name),
     "Set a parser"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_exec_wasi, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_exec_wasi, interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
    {
      FLB_CONFIG_MAP_SIZE, "buf_size", DEFAULT_BUF_SIZE,
      0, FLB_TRUE, offsetof(struct flb_exec_wasi, buf_size),
      "Set the buffer size"
    },
    {
      FLB_CONFIG_MAP_BOOL, "bool", "false",
      0, FLB_TRUE, offsetof(struct flb_exec_wasi, oneshot),
      "execute the command only once"
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_exec_wasi_plugin = {
    .name         = "exec_wasi",
    .description  = "Exec WASI Input",
    .cb_init      = in_exec_wasi_init,
    .cb_pre_run   = in_exec_wasi_prerun,
    .cb_collect   = in_exec_wasi_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_exec_wasi_exit,
    .config_map   = config_map
};
