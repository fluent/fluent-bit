/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>
#include "stdlib.h"

#include "sampling.h"

#include <stdio.h>
#include <sys/types.h>

static void get_numerator_denominator(double frac, unsigned int *numerator, unsigned int *denominator)
{
    double num;
    double den;
    int idx;
    int decimal;

    for (idx = 2; idx <= 1000; idx++) {
        den = (double)idx;
        num = (frac / (1.0/den));
        *numerator = (unsigned int)num;
        *denominator = (unsigned int)den;

        decimal = (int)num;
        if (((num - ((double)decimal)) * 100.0) < 1.0) {
            break;
        }
    }
}

static int configure(struct flb_filter_sampling_ctx *ctx, struct flb_filter_instance *f_ins)
{
    int ret;

    ret = flb_filter_config_map_set(f_ins, ctx);

    if (ret == -1)  {
        flb_plg_error(f_ins, "unable to load configuration");
        return -1;
    }

    if (ctx->rate > 1.0 || ctx->rate < 0.0) {
        flb_plg_warn(ctx->ins, "rate is outside acceptable range: %f, setting to %s", 
                     ctx->rate, SAMPLE_DEFAULT_RATE);
        ctx->rate = strtod(SAMPLE_DEFAULT_RATE, NULL);
    }

    if (ctx->random_enabled == FLB_FALSE) {
        get_numerator_denominator(ctx->rate, &ctx->comb_bands, &ctx->comb_steps);
        flb_plg_debug(ctx->ins, "sampling bands=%d steps=%d", ctx->comb_bands, ctx->comb_steps);
    }

    return 0;
}

static int cb_sampling_init(struct flb_filter_instance *f_ins,
                            struct flb_config *config,
                            void *data)
{
    int ret;
    struct flb_filter_sampling_ctx *ctx;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_filter_sampling_ctx));

    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = f_ins;

    /* parse plugin configuration  */
    ret = configure(ctx, f_ins);

    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set our context */
    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int cb_sampling_filter(const void *data, size_t bytes,
                              const char *tag, int tag_len,
                              void **out_buf, size_t *out_size,
                              struct flb_filter_instance *f_ins,
                              struct flb_input_instance *i_ins,
                              void *context,
                              struct flb_config *config)
{
    int ret;
    int rnum;
    int new_size = 0;
    int old_size = 0;
    double rperc;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct flb_filter_sampling_ctx *ctx = (struct flb_filter_sampling_ctx *)context;

    (void) f_ins;
    (void) i_ins;
    (void) config;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(f_ins,
                      "Log event decoder initialization error : %d", ret);
        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(f_ins,
                      "Log event encoder initialization error : %d", ret);
        flb_log_event_decoder_destroy(&log_decoder);
        return FLB_FILTER_NOTOUCH;
    }

    /* Iterate each item array and apply rules */
    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        old_size++;

        if (ctx->random_enabled == FLB_FALSE) {

            if (ctx->comb_curstep >= ctx->comb_steps) {
                ctx->comb_curstep = 0;
                ctx->comb_curband = 0;
            }
            else if (ctx->comb_curband >= ctx->comb_bands) {
                ctx->comb_curband = 0;
            }

            ctx->comb_curstep++;
            ctx->comb_curband++;

            ret = (ctx->comb_curstep % ctx->comb_steps) < ctx->comb_bands ?
                  SAMPLE_RET_KEEP : SAMPLE_RET_DROP;
            flb_plg_debug(ctx->ins, "combed: ret=%s comb[%d/%d]=%d/%d", 
                          (ret == SAMPLE_RET_KEEP ? "keep" : "drop"),
                          ctx->comb_curband, ctx->comb_curstep, ctx->comb_bands, ctx->comb_steps);
        }
        else {
            rnum = rand_r(&ctx->seed);
            rperc = ((double)abs(rnum)) / ((double)INT_MAX);
            ret = (rperc <= ctx->rate) ? SAMPLE_RET_KEEP : SAMPLE_RET_DROP;
            flb_plg_debug(ctx->ins, "random: ret=%s rnum=%d/rperc=%f (rate=%f)",
                          (ret == SAMPLE_RET_KEEP ? "keep" : "drop"),
                          rnum, rperc, ctx->rate);
        }

        if (ret == SAMPLE_RET_KEEP) {
            ret = flb_log_event_encoder_emit_raw_record(
                        &log_encoder,
                        &((char *) data)[log_decoder.previous_offset],
                        log_decoder.record_length);

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                new_size++;
            }
        }
    }

    /* we keep everything ? */
    if (old_size == new_size) {
        /* Destroy the buffer to avoid more overhead */
        ret = FLB_FILTER_NOTOUCH;
    }
    else {
        *out_buf  = log_encoder.output_buffer;
        *out_size = log_encoder.output_length;

        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);

        ret = FLB_FILTER_MODIFIED;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return ret;
}

static int cb_sampling_exit(void *data, struct flb_config *config)
{
    struct flb_filter_sampling_ctx *ctx = data;

    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_DOUBLE, "rate", SAMPLE_DEFAULT_RATE,
     0, FLB_TRUE, offsetof(struct flb_filter_sampling_ctx, rate),
     "Set sampling"
    },
    {
     FLB_CONFIG_MAP_BOOL, "random", SAMPLE_DEFAULT_RANDOM,
     0, FLB_TRUE, offsetof(struct flb_filter_sampling_ctx, random_enabled),
     "Use random sampling instead of a comb filter"
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_sampling_plugin = {
    .name         = "sampling",
    .description  = "Sample messages using either random comparison or a comb-based state filter",
    .cb_init      = cb_sampling_init,
    .cb_filter    = cb_sampling_filter,
    .cb_exit      = cb_sampling_exit,
    .config_map   = config_map,
    .flags        = 0
};
