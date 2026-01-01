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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <msgpack.h>

struct flb_alter_size {
    int add;
    int remove;
    struct flb_log_event_decoder *log_decoder;
    struct flb_log_event_encoder *log_encoder;
};

static int cb_alter_size_init(struct flb_filter_instance *ins,
                              struct flb_config *config,
                              void *data)
{
    int ret;
    (void) data;
    struct flb_alter_size *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_alter_size));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->log_decoder = flb_log_event_decoder_create(NULL, 0);

    if (ctx->log_decoder == NULL) {
        flb_plg_error(ins, "could not initialize event decoder");

        flb_free(ctx);

        return -1;
    }

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(ins, "could not initialize event encoder");

        flb_log_event_decoder_destroy(ctx->log_decoder);
        flb_free(ctx);

        return -1;
    }

    ret = flb_filter_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_log_event_decoder_destroy(ctx->log_decoder);
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    if (ctx->add > 0 && ctx->remove > 0) {
        flb_plg_error(ins, "cannot use 'add' and 'remove' at the same time");
        flb_log_event_decoder_destroy(ctx->log_decoder);
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(ins, ctx);
    return 0;
}

static int cb_alter_size_filter(const void *data, size_t bytes,
                                const char *tag, int tag_len,
                                void **out_buf, size_t *out_size,
                                struct flb_filter_instance *ins,
                                struct flb_input_instance *i_ins,
                                void *filter_context,
                                struct flb_config *config)
{
    int i;
    int len;
    int ret;
    int total;
    int count = 0;
    char tmp[32];
    struct flb_log_event event;
    struct flb_alter_size *ctx;

    (void) config;
    (void) i_ins;

    ctx = (struct flb_alter_size *) filter_context;

    if (ctx->add > 0) {
        flb_plg_debug(ins, "add %i records", ctx->add);

        /* append old data */
        ret = flb_log_event_encoder_emit_raw_record(
                ctx->log_encoder, data, bytes);

        for (i = 0; i < ctx->add; i++) {
            ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
            }

            len = snprintf(tmp, sizeof(tmp) - 1, "alter_size %i", i);

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_values(
                        ctx->log_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("key"),
                        FLB_LOG_EVENT_STRING_VALUE(tmp, len));
            }
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
        }
    }
    else if (ctx->remove > 0) {
        flb_plg_debug(ins, "remove %i records", ctx->remove);
        count = 0;

        /* Count number of current items */
        total = flb_mp_count(data, bytes);
        total -= ctx->remove;
        if (total <= 0) {
            /* zero records */
            goto exit;
        }

        ret = flb_log_event_decoder_init(ctx->log_decoder,
                                         (char *) data,
                                         bytes);

        while (count < total &&
               flb_log_event_decoder_next(
                ctx->log_decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {

            ret = flb_log_event_encoder_emit_raw_record(
                    ctx->log_encoder,
                    ctx->log_decoder->record_base,
                    ctx->log_decoder->record_length);

            count++;
        }
    }

    exit:
    /* link new buffers */
    *out_buf  = ctx->log_encoder->output_buffer;
    *out_size = ctx->log_encoder->output_length;

    flb_log_event_encoder_claim_internal_buffer_ownership(
        ctx->log_encoder);

    return FLB_FILTER_MODIFIED;
}

static int cb_alter_size_exit(void *data, struct flb_config *config)
{
    (void) config;
    struct flb_alter_size *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_INT, "add", "0",
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_alter_size, add),
     "add N records to the chunk"
    },
    {
     FLB_CONFIG_MAP_INT, "remove", "0",
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_alter_size, remove),
     "remove N records from the chunk"
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_alter_size_plugin = {
    .name         = "alter_size",
    .description  = "Alter incoming chunk size",
    .cb_init      = cb_alter_size_init,
    .cb_filter    = cb_alter_size_filter,
    .cb_exit      = cb_alter_size_exit,
    .config_map   = config_map,
    .flags        = 0
};
