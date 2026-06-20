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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "in_exec_win32_compat.h"

#include "in_exec.h"

/* cb_collect callback */
static int in_exec_collect(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    int ret = -1;
    int cmdret;
    int flb_exit_code;
    uint64_t val;
    size_t str_len = 0;
    FILE *cmdp = NULL;
    struct flb_exec *ctx = in_context;

    /* variables for parser */
    int parser_ret = -1;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;

    if (ctx->oneshot == FLB_TRUE) {
        ret = flb_pipe_r(ctx->ch_manager[0], &val, sizeof(val));
        if (ret == -1) {
            flb_pipe_error();
            return -1;
        }
    }

    cmdp = flb_popen(ctx->cmd, "r");
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

                ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_set_timestamp(
                            &ctx->log_encoder,
                            &out_time);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                            &ctx->log_encoder,
                            out_buf,
                            out_size);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    flb_input_log_append(ctx->ins, NULL, 0,
                                         ctx->log_encoder.output_buffer,
                                         ctx->log_encoder.output_length);

                }
                else {
                    flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
                }

                flb_log_event_encoder_reset(&ctx->log_encoder);

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

            ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_set_current_timestamp(
                        &ctx->log_encoder);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_cstring(
                        &ctx->log_encoder, "exec");
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_string(
                        &ctx->log_encoder,
                        ctx->buf,
                        str_len);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                flb_input_log_append(ctx->ins, NULL, 0,
                                     ctx->log_encoder.output_buffer,
                                     ctx->log_encoder.output_length);

            }
            else {
                flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
            }

            flb_log_event_encoder_reset(&ctx->log_encoder);
        }
    }

    ret = 0; /* success */

 collect_end:
    if(cmdp != NULL){
        /*
         * If we're propagating the child exit code to the fluent-bit exit code
         * in one-shot mode, popen() will have invoked our child command via
         * its own shell, so unless the shell itself exited on a signal the
         * translation is already done for us.
         * For references on exit code handling in wrappers see
         * https://www.gnu.org/software/bash/manual/html_node/Exit-Status.html
         * and
         * https://skarnet.org/software/execline/exitcodes.html
         */
        cmdret = flb_pclose(cmdp);
        if (cmdret == -1) {
            flb_errno();
            flb_plg_debug(ctx->ins,
                    "unexpected error while waiting for exit of command %s ",
                    ctx->cmd);
            /*
             * The exit code of the shell run by popen() could not be
             * determined; exit with 128, which is not a code that could be
             * returned through a shell by a real child command.
             */
            flb_exit_code = 128;
        } else if (FLB_WIFEXITED(cmdret)) {
            flb_plg_debug(ctx->ins, "command %s exited with code %d",
                    ctx->cmd, FLB_WEXITSTATUS(cmdret));
            /*
             * Propagate shell exit code, which may encode a normal or signal
             * exit for the real child process, directly to the caller. This
             * could be greater than 127 if the shell encoded a signal exit
             * status from the child process into its own return code.
             */
            flb_exit_code = FLB_WEXITSTATUS(cmdret);
        } else if (FLB_WIFSIGNALED(cmdret)) {
            flb_plg_debug(ctx->ins, "command %s exited with signal %d",
                    ctx->cmd, FLB_WTERMSIG(cmdret));
            /*
             * Follow the shell convention of returning 128+signo for signal
             * exits. The consumer of fluent-bit's exit code will be unable to
             * differentiate between the shell exiting on a signal and the
             * process called by the shell exiting on a signal.
             */
            flb_exit_code = 128 + FLB_WTERMSIG(cmdret);
        } else {
            flb_plg_debug(ctx->ins, "command %s exited with unknown status",
                    ctx->cmd);
            flb_exit_code = 128;
        }

        /*
         * In one-shot mode, exit fluent-bit once the child process terminates.
         */
        if (ctx->exit_after_oneshot == FLB_TRUE) {
            /*
             * propagate the child process exit code as the fluent-bit exit
             * code so fluent-bit with the exec plugin can be used as a
             * command wrapper.
             */
            if (ctx->propagate_exit_code == FLB_TRUE) {
                config->exit_status_code = flb_exit_code;
            }
            flb_plg_info(ctx->ins,
                    "one-shot command exited, terminating fluent-bit");
            flb_engine_exit(config);
        } else {
            flb_plg_debug(ctx->ins,
                    "one-shot command exited but exit_after_oneshot not set");
        }
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

    /*
     * propagate_exit_code is not being forced to imply exit_after_oneshot in
     * case somebody in future wishes to make the exec plugin exit on nonzero
     * exit codes for normal repeating commands.
     */
    if (ctx->propagate_exit_code && !ctx->exit_after_oneshot) {
        flb_plg_error(in,
                "propagate_exit_code=True option makes no sense without "
                "exit_after_oneshot=True");
        return -1;
    }

    if (ctx->exit_after_oneshot && !ctx->oneshot) {
        flb_plg_debug(in, "exit_after_oneshot implies oneshot mode, enabling");
        ctx->oneshot = FLB_TRUE;
    }

    if (ctx->oneshot) {
        ctx->interval_sec = -1;
        ctx->interval_nsec = -1;
    }

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(in, "error initializing event encoder : %d", ret);

        return -1;
    }

    flb_plg_debug(in, "interval_sec=%d interval_nsec=%d oneshot=%i buf_size=%zu",
              ctx->interval_sec, ctx->interval_nsec, ctx->oneshot, ctx->buf_size);

    return 0;
}

static void delete_exec_config(struct flb_exec *ctx)
{
    if (!ctx) {
        return;
    }

    flb_log_event_encoder_destroy(&ctx->log_encoder);

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
        flb_pipe_error();
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
    {
      FLB_CONFIG_MAP_BOOL, "exit_after_oneshot", "false",
      0, FLB_TRUE, offsetof(struct flb_exec, exit_after_oneshot),
      "exit fluent-bit after the command terminates in one-shot mode"
    },
    {
      FLB_CONFIG_MAP_BOOL, "propagate_exit_code", "false",
      0, FLB_TRUE, offsetof(struct flb_exec, propagate_exit_code),
      "propagate oneshot exit command fluent-bit exit code using "
      "shell exit code translation conventions"
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
