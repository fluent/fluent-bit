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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include "in_lib.h"

static int in_lib_collect(struct flb_input_instance *ins,
                          struct flb_config *config, void *in_context)
{
    int ret;
    int dec_ret;
    int enc_ret;
    int bytes;
    int out_size;
    int capacity;
    int size;
    char *ptr;
    char *pack;
    struct flb_log_event record;
    struct flb_log_event_decoder decoder;
    struct flb_in_lib_config *ctx = in_context;

    capacity = (ctx->buf_size - ctx->buf_len);

    /* Allocate memory as required (FIXME: this will be limited in later) */
    if (capacity == 0) {
        size = ctx->buf_size + LIB_BUF_CHUNK;
        ptr = flb_realloc(ctx->buf_data, size);
        if (!ptr) {
            flb_errno();
            return -1;
        }
        ctx->buf_data = ptr;
        ctx->buf_size = size;
        capacity = LIB_BUF_CHUNK;
    }

    bytes = flb_pipe_r(ctx->fd,
                       ctx->buf_data + ctx->buf_len,
                       capacity);
    flb_plg_trace(ctx->ins, "in_lib read() = %i", bytes);
    if (bytes == -1) {
        perror("read");
        flb_pipe_error();
        if (errno == -EPIPE) {
            return -1;
        }
        return 0;
    }
    ctx->buf_len += bytes;

    /* initially we should support json input */
    ret = flb_pack_json_state(ctx->buf_data, ctx->buf_len,
                              &pack, &out_size, &ctx->state);
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_warn(ctx->ins, "lib data incomplete, waiting for more data...");
        return 0;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(ctx->ins, "lib data invalid");
        flb_pack_state_reset(&ctx->state);
        flb_pack_state_init(&ctx->state);
        return -1;
    }
    ctx->buf_len = 0;

    dec_ret = flb_log_event_decoder_init(&decoder, pack, out_size);
    if (dec_ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %s",
                      flb_log_event_decoder_get_error_description(dec_ret));
        flb_free(pack);
        flb_pack_state_reset(&ctx->state);
        flb_pack_state_init(&ctx->state);
        return -1;
    }

    while ((dec_ret = flb_log_event_decoder_next(
                      &decoder,
                      &record)) == FLB_EVENT_DECODER_SUCCESS) {
        enc_ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);
        if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "flb_log_event_encoder_begin_record error : %s",
                          flb_log_event_encoder_get_error_description(enc_ret));
            flb_log_event_encoder_rollback_record(&ctx->log_encoder);
            continue;
        }

        enc_ret = flb_log_event_encoder_set_timestamp(
                  &ctx->log_encoder,
                  &record.timestamp);
        if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "flb_log_event_encoder_set_timestamp error : %s",
                          flb_log_event_encoder_get_error_description(enc_ret));
            flb_log_event_encoder_rollback_record(&ctx->log_encoder);
            continue;
        }

        enc_ret = flb_log_event_encoder_set_metadata_from_msgpack_object(
                  &ctx->log_encoder,
                  record.metadata);
        if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "flb_log_event_encoder_set_metadata_from_msgpack_object error : %s",
                          flb_log_event_encoder_get_error_description(enc_ret));
            flb_log_event_encoder_rollback_record(&ctx->log_encoder);
            continue;
        }

        enc_ret = flb_log_event_encoder_set_body_from_msgpack_object(
                  &ctx->log_encoder,
                  record.body);
        if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "flb_log_event_encoder_set_body_from_msgpack_object error : %s",
                          flb_log_event_encoder_get_error_description(enc_ret));
            flb_log_event_encoder_rollback_record(&ctx->log_encoder);
            continue;
        }

        enc_ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
        if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "flb_log_event_encoder_commit_record error : %s",
                          flb_log_event_encoder_get_error_description(enc_ret));
            flb_log_event_encoder_rollback_record(&ctx->log_encoder);
            continue;
        }
    }

    dec_ret = flb_log_event_decoder_get_last_result(&decoder);
    if (dec_ret == FLB_EVENT_DECODER_SUCCESS) {
        flb_input_log_append(ctx->ins, NULL, 0,
                             ctx->log_encoder.output_buffer,
                             ctx->log_encoder.output_length);

        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins,
                      "flb_log_event_decoder_get_last_result error : %s",
                      flb_log_event_decoder_get_error_description(dec_ret));
        ret = -1;
    }

    flb_log_event_encoder_reset(&ctx->log_encoder);
    flb_log_event_decoder_destroy(&decoder);

    /* Reset the state */
    flb_free(pack);

    flb_pack_state_reset(&ctx->state);
    flb_pack_state_init(&ctx->state);

    return ret;
}

/* Initialize plugin */
static int in_lib_init(struct flb_input_instance *in,
                       struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_lib_config *ctx;
    (void) data;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_in_lib_config));
    if (!ctx) {
        return -1;
    }
    ctx->ins = in;

    /* Buffer for incoming data */
    ctx->buf_size = LIB_BUF_CHUNK;
    ctx->buf_data = flb_calloc(1, LIB_BUF_CHUNK);
    ctx->buf_len = 0;

    if (!ctx->buf_data) {
        flb_errno();
        flb_plg_error(ctx->ins, "Could not allocate initial buf memory buffer");
        flb_free(ctx);
        return -1;
    }

    /* Init communication channel */
    flb_input_channel_init(in);
    ctx->fd = in->channel[0];

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_event(in,
                                        in_lib_collect,
                                        ctx->fd,
                                        config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for LIB input plugin");
        flb_free(ctx->buf_data);
        flb_free(ctx);
        return -1;
    }

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);

        flb_free(ctx->buf_data);
        flb_free(ctx);

        return -1;
    }

    flb_pack_state_init(&ctx->state);

    return 0;
}

static int in_lib_exit(void *data, struct flb_config *config)
{
    struct flb_in_lib_config *ctx = data;
    struct flb_pack_state *s;

    (void) config;

    flb_log_event_encoder_destroy(&ctx->log_encoder);

    if (ctx->buf_data) {
        flb_free(ctx->buf_data);
    }

    s = &ctx->state;
    flb_pack_state_reset(s);
    flb_free(ctx);
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_lib_plugin = {
    .name         = "lib",
    .description  = "Library mode Input",
    .cb_init      = in_lib_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_ingest    = NULL,
    .cb_flush_buf = NULL,
    .cb_exit      = in_lib_exit
};
