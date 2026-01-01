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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DEFAULT_INTERVAL_SEC  "1"
#define DEFAULT_INTERVAL_NSEC "0"

struct flb_in_random_config {
    /* Config properties */
    int              interval_sec;
    int              interval_nsec;
    int              samples;

    /* Internal */
    int              samples_count;
    int              coll_fd;

    struct flb_input_instance *ins;
    struct flb_log_event_encoder *log_encoder;
};

/* cb_collect callback */
static int in_random_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    int ret;
    uint64_t val;
    struct flb_in_random_config *ctx = in_context;

    if (ctx->samples == 0) {
        return -1;
    }

    if (ctx->samples > 0 && (ctx->samples_count >= ctx->samples)) {
        return -1;
    }

    if (flb_random_bytes((unsigned char *) &val, sizeof(uint64_t))) {
        val = time(NULL);
    }

    ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
                ctx->log_encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("rand_value"),
                FLB_LOG_EVENT_UINT64_VALUE(val));
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(ctx->ins, NULL, 0,
                             ctx->log_encoder->output_buffer,
                             ctx->log_encoder->output_length);
        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "log event encoding error : %d", ret);

        ret = -1;
    }

    flb_log_event_encoder_reset(ctx->log_encoder);

    ctx->samples_count++;

    return 0;
}

/* Set plugin configuration */
static int in_random_config_read(struct flb_in_random_config *ctx,
                                 struct flb_input_instance *in)
{
    int ret;
    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        return -1;
    }
    
    /* interval settings */
    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
    }


    flb_plg_debug(ctx->ins, "interval_sec=%d interval_nsec=%d",
                  ctx->interval_sec, ctx->interval_nsec);

    return 0;
}

/* Initialize plugin */
static int in_random_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_in_random_config *ctx = NULL;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_random_config));
    if (!ctx) {
        return -1;
    }
    ctx->samples_count = 0;
    ctx->ins = in;

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(in, "could not initialize event encoder");
        flb_free(ctx);

        return -1;
    }

    /* Initialize head config */
    ret = in_random_config_read(ctx, in);
    if (ret < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_input_set_context(in, ctx);
    ret = flb_input_set_collector_time(in,
                                       in_random_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec, config);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not set collector for head input plugin");
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;
    return 0;
}

static void in_random_pause(void *data, struct flb_config *config)
{
    struct flb_in_random_config *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);

}

static void in_random_resume(void *data, struct flb_config *config)
{
    struct flb_in_random_config *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int in_random_exit(void *data, struct flb_config *config)
{
    struct flb_in_random_config *ctx = data;
    (void) *config;

    if (!ctx) {
        return 0;
    }

    if (ctx->log_encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    flb_free(ctx);
    return 0;
}


static struct flb_config_map config_map[] = {
    // samples
    // interval_sec
    // interval_nsec
    {
     FLB_CONFIG_MAP_INT, "samples", "-1",
     0, FLB_TRUE, offsetof(struct flb_in_random_config, samples),
     "Number of samples to send, -1 for infinite"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_in_random_config, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_in_random_config, interval_nsec),
      "Set the collector interval (sub seconds)"
    },
    /* EOF */
    {0}
    
};

struct flb_input_plugin in_random_plugin = {
    .name         = "random",
    .description  = "Random",
    .cb_init      = in_random_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_random_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_random_pause,
    .cb_resume    = in_random_resume,
    .cb_exit      = in_random_exit,
    .config_map   = config_map
};
