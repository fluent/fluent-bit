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
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter_wasm.h"

/* cb_filter callback */
static int cb_wasm_filter(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          void **out_buf, size_t *out_bytes,
                          struct flb_filter_instance *f_ins,
                          struct flb_input_instance *i_ins,
                          void *filter_context,
                          struct flb_config *config)
{
    int ret;
    char *ret_val = NULL;
    char *buf = NULL;

    size_t off = 0;
    size_t last_off = 0;
    size_t alloc_size = 0;
    char *json_buf = NULL;
    size_t json_size;
    int root_type;
    /* Get the persistent WASM instance from the filter context. */
    struct flb_filter_wasm *ctx = filter_context;
    struct flb_wasm *wasm = ctx->wasm;
    size_t buf_size;

    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    (void) f_ins;
    (void) i_ins;
    (void) config;

    /* Safeguard in case initialization failed. */
    if (!wasm) {
        flb_plg_error(ctx->ins, "WASM instance is not available, skipping.");
        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FILTER_NOTOUCH;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        off = log_decoder.offset;
        alloc_size = (off - last_off) + 128; /* JSON is larger than msgpack */
        last_off = off;
        switch(ctx->event_format) {
        case FLB_FILTER_WASM_FMT_JSON:
            /* Encode as JSON from msgpack */
            buf = flb_msgpack_to_json_str(alloc_size, log_event.body, config->json_escape_unicode);

            if (buf) {
                /* Execute WASM program */
                ret_val = flb_wasm_call_function_format_json(wasm, ctx->wasm_function_name,
                                                             tag, tag_len,
                                                             log_event.timestamp,
                                                             buf, strlen(buf));

                flb_free(buf);
            }
            else {
                flb_plg_error(ctx->ins, "encode as JSON from msgpack is failed");
                /* Go to on_error without destroying the persistent wasm instance */
                goto on_error_without_wasm_destroy;
            }
            break;
        case FLB_FILTER_WASM_FMT_MSGPACK:
            ret = flb_wasm_format_msgpack_mode(tag, tag_len,
                                               &log_event,
                                               (void **)&buf, &buf_size);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "format msgpack is failed");
                /* Go to on_error without destroying the persistent wasm instance */
                goto on_error_without_wasm_destroy;
            }

            /* Execute WASM program */
            ret_val = flb_wasm_call_function_format_msgpack(wasm, ctx->wasm_function_name,
                                                            tag, tag_len,
                                                            log_event.timestamp,
                                                            buf, buf_size);

            flb_free(buf);
            break;
        }

        if (ret_val == NULL) { /* Skip record */
            flb_plg_debug(ctx->ins, "encode as JSON from msgpack is broken. Skip.");
            continue;
        }

        if (ctx->event_format == FLB_FILTER_WASM_FMT_JSON &&
            strlen(ret_val) == 0) { /* Skip record */
            flb_plg_debug(ctx->ins, "WASM function returned empty string. Skip.");
            flb_free(ret_val);
            continue;
        }

        ret = flb_log_event_encoder_begin_record(&log_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_timestamp(
                    &log_encoder, &log_event.timestamp);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_metadata_from_msgpack_object(
                    &log_encoder,
                    log_event.metadata);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            switch(ctx->event_format) {
            case FLB_FILTER_WASM_FMT_JSON:
                /* Convert JSON payload to msgpack */
                ret = flb_pack_json(ret_val, strlen(ret_val),
                                    &json_buf, &json_size, &root_type, NULL);

                if (ret == 0 && root_type == JSMN_OBJECT) {
                    /* JSON found, pack it msgpack representation */
                    ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                            &log_encoder,
                            json_buf,
                            json_size);

                    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                        ret = flb_log_event_encoder_commit_record(&log_encoder);
                    }
                    else {
                        flb_log_event_encoder_rollback_record(&log_encoder);
                    }
                }
                else {
                    flb_plg_error(ctx->ins, "invalid JSON format. ret: %d, buf: %s", ret, ret_val);

                    flb_log_event_encoder_rollback_record(&log_encoder);
                }
                break;
            case FLB_FILTER_WASM_FMT_MSGPACK:
                /* msgpack found, pack it msgpack representation */
                ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                        &log_encoder,
                        ret_val,
                        strlen(ret_val));

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_commit_record(&log_encoder);
                }
                else {
                    flb_log_event_encoder_rollback_record(&log_encoder);
                }

                break;
            }
        }
        else {
            flb_log_event_encoder_rollback_record(&log_encoder);
        }

        /* release 'ret_val' if it was allocated */
        if (ret_val != NULL) {
            flb_free(ret_val);
        }

        if (ctx->event_format == FLB_FILTER_WASM_FMT_JSON) {
            /* release 'json_buf' if it was allocated */
            if (json_buf != NULL) {
                flb_free(json_buf);
            }
        }
    }

    *out_buf   = log_encoder.output_buffer;
    *out_bytes = log_encoder.output_length;

    flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return FLB_FILTER_MODIFIED;

/* A new error handler that doesn't destroy the persistent wasm instance */
on_error_without_wasm_destroy:
    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);
    return FLB_FILTER_NOTOUCH;
}

/* read config file and*/
static int filter_wasm_config_read(struct flb_filter_wasm *ctx,
                                   struct flb_filter_instance *f_ins,
                                   struct flb_config *config)
{
    int ret;

    ctx->ins = f_ins;

    /* Load the config map */
    ret = flb_filter_config_map_set(f_ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(f_ins, "unable to load configuration");
        return -1;
    }

    /* filepath setting */
    if (ctx->wasm_path == NULL) {
        flb_plg_error(f_ins, "no WASM 'program path' was given");
        return -1;
    }

    /* function_name setting */
    if (ctx->wasm_function_name == NULL) {
        flb_plg_error(f_ins, "no WASM 'function name' was given");
        return -1;
    }

    return 0;
}

static void delete_wasm_config(struct flb_filter_wasm *ctx)
{
    if (!ctx) {
        return;
    }

    flb_free(ctx);
}

/* Check existence of wasm program binary */
static int cb_wasm_pre_run(struct flb_filter_instance *f_ins,
                           struct flb_config *config, void *data)
{
    struct flb_filter_wasm *ctx = NULL;
    int ret = -1;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_filter_wasm));
    if (!ctx) {
        return -1;
    }

    /* Initialize exec config */
    ret = filter_wasm_config_read(ctx, f_ins, config);
    if (ret < 0) {
        goto pre_run_error;
    }

    /* Check accessibility for the wasm path */
    ret = access(ctx->wasm_path, R_OK);
    if (ret != 0) {
        flb_plg_error(f_ins, "cannot access wasm program at %s", ctx->wasm_path);
        goto pre_run_error;
    }

    delete_wasm_config(ctx);

    return 0;

pre_run_error:
    delete_wasm_config(ctx);

    return -1;
}

/* Initialize plugin */
static int cb_wasm_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config, void *data)
{
    struct flb_filter_wasm *ctx = NULL;
    struct flb_wasm_config *wasm_conf = NULL;
    int ret = -1;
    const char *tmp;
    int event_format;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_filter_wasm));
    if (!ctx) {
        return -1;
    }
    /* Initialize wasm pointer to NULL */
    ctx->wasm = NULL;


    /* Initialize exec config */
    ret = filter_wasm_config_read(ctx, f_ins, config);
    if (ret < 0) {
        goto init_error;
    }

    tmp = flb_filter_get_property("event_format", f_ins);
    if (tmp) {
        if (strcasecmp(tmp, FLB_FMT_STR_JSON) == 0) {
            event_format = FLB_FILTER_WASM_FMT_JSON;
        }
        else if (strcasecmp(tmp, FLB_FMT_STR_MSGPACK) == 0) {
            event_format = FLB_FILTER_WASM_FMT_MSGPACK;
        } else {
            flb_error("[filter_wasm] unknown format: %s", tmp);
            goto init_error;
        }
        ctx->event_format = event_format;
    } else {
        ctx->event_format = FLB_FILTER_WASM_FMT_JSON;
    }

    flb_wasm_init(config);
    wasm_conf = flb_wasm_config_init(config);
    if (wasm_conf == NULL) {
        goto init_error;
    }
    ctx->wasm_conf = wasm_conf;

    if (ctx->wasm_heap_size > FLB_WASM_DEFAULT_HEAP_SIZE) {
        wasm_conf->heap_size = ctx->wasm_heap_size;
    }
    if (ctx->wasm_stack_size > FLB_WASM_DEFAULT_STACK_SIZE) {
        wasm_conf->stack_size = ctx->wasm_stack_size;
    }

    /* Set context before instantiating */
    flb_filter_set_context(f_ins, ctx);

    /* Instantiate the WASM module once and store it in the context */
    ctx->wasm = flb_wasm_instantiate(config, ctx->wasm_path,
                                     ctx->accessible_dir_list,
                                     ctx->wasm_conf);

    if (ctx->wasm == NULL) {
        flb_plg_error(ctx->ins, "failed to instantiate wasm program: %s",
                      ctx->wasm_path);
        goto init_error;
    }

    return 0;

init_error:
    if (ctx) {
        if (ctx->wasm_conf) {
            flb_wasm_config_destroy(ctx->wasm_conf);
            ctx->wasm_conf = NULL;
        }
        delete_wasm_config(ctx);
    }
    flb_filter_set_context(f_ins, NULL);
    return -1;
}

static int cb_wasm_exit(void *data, struct flb_config *config)
{
    struct flb_filter_wasm *ctx = data;

    if (!ctx) {
        return 0;
    }

    /* Destroy the single, persistent WASM instance */
    if (ctx->wasm) {
        flb_wasm_destroy(ctx->wasm);
    }
    /* Destroy the WASM configuration */
    if (ctx->wasm_conf) {
        flb_wasm_config_destroy(ctx->wasm_conf);
    }
    delete_wasm_config(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "event_format", NULL,
     0, FLB_FALSE, 0,
     "Sepecify the ingesting event format for wasm program"
    },
    {
     FLB_CONFIG_MAP_STR, "wasm_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_filter_wasm, wasm_path),
     "Set the wasm path to execute"
    },
    {
     FLB_CONFIG_MAP_CLIST, "accessible_paths", ".",
     0, FLB_TRUE, offsetof(struct flb_filter_wasm, accessible_dir_list),
     "Specifying paths to be accessible from a WASM program."
     "Default value is current working directory"
    },
    {
     FLB_CONFIG_MAP_STR, "function_name", NULL,
     0, FLB_TRUE, offsetof(struct flb_filter_wasm, wasm_function_name),
     "Set the function name in wasm to execute"
    },
    {
      FLB_CONFIG_MAP_SIZE, "wasm_heap_size", DEFAULT_WASM_HEAP_SIZE,
      0, FLB_TRUE, offsetof(struct flb_filter_wasm, wasm_heap_size),
      "Set the heap size of wasm runtime"
    },
    {
      FLB_CONFIG_MAP_SIZE, "wasm_stack_size", DEFAULT_WASM_STACK_SIZE,
      0, FLB_TRUE, offsetof(struct flb_filter_wasm, wasm_stack_size),
      "Set the stack size of wasm runtime"
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_wasm_plugin = {
    .name         = "wasm",
    .description  = "WASM program filter",
    .cb_pre_run   = cb_wasm_pre_run,
    .cb_init      = cb_wasm_init,
    .cb_filter    = cb_wasm_filter,
    .cb_exit      = cb_wasm_exit,
    .config_map   = config_map
};
