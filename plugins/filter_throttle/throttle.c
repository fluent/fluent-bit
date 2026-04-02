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

#include "throttle.h"
#include "window.h"

#include <stdio.h>
#include <sys/types.h>

pthread_mutex_t throttle_mut;


static bool apply_suffix (double *x, char suffix_char)
{
  int multiplier;

  switch (suffix_char)
    {
    case 0:
    case 's':
      multiplier = 1;
      break;
    case 'm':
      multiplier = 60;
      break;
    case 'h':
      multiplier = 60 * 60;
      break;
    case 'd':
      multiplier = 60 * 60 * 24;
      break;
    default:
      return false;
    }

  *x *= multiplier;

  return true;
}


void *time_ticker(void *args)
{
    struct flb_time ftm;
    long timestamp;
    struct flb_filter_throttle_ctx *ctx = args;

    while (1) {
        flb_time_get(&ftm);
        timestamp = flb_time_to_double(&ftm);
        pthread_mutex_lock(&throttle_mut);
        window_add(ctx->hash, timestamp, 0);

        ctx->hash->current_timestamp = timestamp;

        if (ctx->print_status) {
            flb_plg_info(ctx->ins,
                         "%ld: limit is %0.2f per %s with window size of %i, retain is %d, "
                         "current rate is: %i per interval",
                         timestamp, t->ctx->max_rate, t->ctx->slide_interval,
                         t->ctx->window_size,  t->ctx->retain_data,
                         t->ctx->hash->total / t->ctx->hash->size);
        }
        pthread_mutex_unlock(&throttle_mut);
        /* sleep is a cancelable function */
        sleep(ctx->ticker_data.seconds);
    }
}

/* Given a msgpack record, do some filter action based on the defined rules */
static inline int throttle_data(struct flb_filter_throttle_ctx *ctx)
{
    if ((ctx->hash->total / (double) ctx->hash->size) >= ctx->max_rate) {
        return THROTTLE_RET_DROP;
    }

    window_add(ctx->hash, ctx->hash->current_timestamp, 1);

    return THROTTLE_RET_KEEP;
}

static inline bool get_retain(struct flb_filter_throttle_ctx *ctx)
{
    if (ctx->retain_data) {
        return true;
    }

    return false;
}

static int configure(struct flb_filter_throttle_ctx *ctx, struct flb_filter_instance *f_ins)
{
    int ret;

    ret = flb_filter_config_map_set(f_ins, ctx);
    if (ret == -1)  {
        flb_plg_error(f_ins, "unable to load configuration");
        return -1;
    }
    if (ctx->max_rate <= 1.0) {
        ctx->max_rate = strtod(THROTTLE_DEFAULT_RATE, NULL);
    }
    if (ctx->window_size <= 1) {
        ctx->window_size = strtoul(THROTTLE_DEFAULT_WINDOW, NULL, 10);
    }

    return 0;
}

static int parse_duration(struct flb_filter_throttle_ctx *ctx,
                          const char *interval)
{
    double seconds = 0.0;
    double s;
    char *p;

    s = strtod(interval, &p);
    if  ( 0 >= s
          /* No extra chars after the number and an optional s,m,h,d char.  */
          || (*p && *(p+1))
          /* Check any suffix char and update S based on the suffix.  */
          || ! apply_suffix (&s, *p))
        {
            flb_plg_warn(ctx->ins,
                         "invalid time interval %s falling back to default: 1 "
                         "second",
                         interval);
        }

      seconds += s;
      return seconds;
}

static int cb_throttle_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    struct flb_filter_throttle_ctx *ctx;

    pthread_mutex_init(&throttle_mut, NULL);

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_filter_throttle_ctx));
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

    ctx->hash = window_create(ctx->window_size);

    ctx->ticker_data.seconds = parse_duration(ctx, ctx->slide_interval);
    pthread_create(&ctx->ticker_data.thr, NULL, &time_ticker, ctx);
    return 0;
}

static int cb_throttle_filter(const void *data, size_t bytes,
                              const char *tag, int tag_len,
                              void **out_buf, size_t *out_size,
                              struct flb_filter_instance *f_ins,
                              struct flb_input_instance *i_ins,
                              void *context,
                              struct flb_config *config)
{
    int ret;
    /* Do not drop some messages if rate limit is exceeded */
    bool retain = false;
    int old_size = 0;
    int new_size = 0;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

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
        pthread_mutex_lock(&throttle_mut);
        ret = throttle_data(context);
        retain = get_retain(context);
        pthread_mutex_unlock(&throttle_mut);

        if (ret == THROTTLE_RET_KEEP) {
            ret = flb_log_event_encoder_emit_raw_record(
                        &log_encoder,
                        &((char *) data)[log_decoder.previous_offset],
                        log_decoder.record_length);

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                new_size++;
            }
        }
        else if (ret == THROTTLE_RET_DROP) {
            /* If Retain is false, Do nothing */
            if (retain) {
                usleep(10 * 1000);
                msgpack_pack_object(&tmp_pck, root);
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

static int cb_throttle_exit(void *data, struct flb_config *config)
{
    void *thr_res;
    struct flb_filter_throttle_ctx *ctx = data;

    int s = pthread_cancel(ctx->ticker_data.thr);
    if (s != 0) {
        flb_plg_error(ctx->ins, "Unable to cancel ticker. Leaking context to avoid memory corruption.");
        return 1;
    }

    s = pthread_join(ctx->ticker_data.thr, &thr_res);
    if (s != 0) {
        flb_plg_error(ctx->ins, "Unable to join ticker. Leaking context to avoid memory corruption.");
        return 1;
    }

    if (thr_res != PTHREAD_CANCELED) {
        flb_plg_error(ctx->ins, "Thread joined but was not canceled which is impossible.");
    }

    flb_free(ctx->hash->table);
    flb_free(ctx->hash);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    // rate
    // window
    // print_status
    // retain
    // interval
    {
     FLB_CONFIG_MAP_DOUBLE, "rate", THROTTLE_DEFAULT_RATE,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_ctx, max_rate),
     "Set throttle rate"
    },
    {
     FLB_CONFIG_MAP_INT, "window", THROTTLE_DEFAULT_WINDOW,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_ctx, window_size),
     "Set throttle window"
    },
    {
     FLB_CONFIG_MAP_BOOL, "print_status", THROTTLE_DEFAULT_STATUS,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_ctx, print_status),
     "Set whether or not to print status information"
    },
    {
     FLB_CONFIG_MAP_BOOL, "retain", THROTTLE_DEFAULT_RETAIN,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_ctx, retain_data),
     "Set whether or not to drop some messages if rate limit is exceeded"
    },
    {
     FLB_CONFIG_MAP_STR, "interval", THROTTLE_DEFAULT_INTERVAL,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_ctx, slide_interval),
     "Set the slide interval"
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_throttle_plugin = {
    .name         = "throttle",
    .description  = "Throttle messages using sliding window algorithm",
    .cb_init      = cb_throttle_init,
    .cb_filter    = cb_throttle_filter,
    .cb_exit      = cb_throttle_exit,
    .config_map   = config_map,
    .flags        = 0
};