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
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define DEFAULT_INTERVAL_SEC  "1"
#define DEFAULT_INTERVAL_NSEC "0"

/* Input configuration & context */
struct flb_in_health_config {
    /* Alert mode */
    int alert;

    /* Append Hostname */
    int add_host;
    int len_host;
    char* hostname;

    /* Append Port Number */
    int add_port;
    int port;

    /* Time interval check */
    int interval_sec;
    int interval_nsec;

    /* Networking */
    struct flb_upstream *u;

    struct flb_log_event_encoder log_encoder;

    /* Plugin instance */
    struct flb_input_instance *ins;
};

/* Collection aims to try to connect to the specified TCP server */
static int in_health_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    uint8_t alive;
    struct flb_in_health_config *ctx = in_context;
    struct flb_connection *u_conn;
    int ret;

    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        alive = FLB_FALSE;
    }
    else {
        alive = FLB_TRUE;
        flb_upstream_conn_release(u_conn);
    }

    if (alive == FLB_TRUE && ctx->alert == FLB_TRUE) {
        FLB_INPUT_RETURN(0);
    }

    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(
                &ctx->log_encoder);
    }

    /* Status */
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
                &ctx->log_encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("alive"),
                FLB_LOG_EVENT_BOOLEAN_VALUE(alive));
    }

    if (ctx->add_host) {
        /* append hostname */
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("hostname"),
                    FLB_LOG_EVENT_CSTRING_VALUE(ctx->hostname));
        }
    }

    if (ctx->add_port) {
        /* append port number */
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("port"),
                    FLB_LOG_EVENT_INT32_VALUE(ctx->port));
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(ins, NULL, 0,
                             ctx->log_encoder.output_buffer,
                             ctx->log_encoder.output_length);

        ret = 0;
    }
    else {
        flb_plg_error(ins, "Error encoding record : %d", ret);

        ret = -1;
    }

    flb_log_event_encoder_reset(&ctx->log_encoder);

    FLB_INPUT_RETURN(ret);
}

static int in_health_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    int upstream_flags;
    struct flb_in_health_config *ctx;
    (void) data;

    if (in->host.name == NULL) {
        flb_plg_error(in, "no input 'Host' provided");
        return -1;
    }

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_health_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->alert = FLB_FALSE;
    ctx->add_host = FLB_FALSE;
    ctx->len_host = 0;
    ctx->hostname = NULL;
    ctx->add_port = FLB_FALSE;
    ctx->port     = -1;
    ctx->ins      = in;


    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        flb_free(ctx);
        flb_plg_error(in, "unable to load configuration");
        return -1;
    }

    upstream_flags = FLB_IO_TCP;

    if (in->use_tls) {
        upstream_flags |= FLB_IO_TLS;
    }

    ctx->u = flb_upstream_create(config, in->host.name, in->host.port,
                                 upstream_flags, in->tls);

    if (!ctx->u) {
        flb_plg_error(ctx->ins, "could not initialize upstream");
        flb_free(ctx);
        return -1;
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
    }

    if (ctx->add_host) {
        ctx->len_host = strlen(in->host.name);
        ctx->hostname = flb_strdup(in->host.name);
    }

    if (ctx->add_port) {
        ctx->port = in->host.port;
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set our collector based on time */
    ret = flb_input_set_collector_time(in,
                                       in_health_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set collector for Health input plugin");
        flb_free(ctx);
        return -1;
    }

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(in, "error initializing event encoder : %d", ret);

        flb_free(ctx);

        return -1;
    }

    return 0;
}

static int in_health_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_health_config *ctx = data;

    flb_log_event_encoder_destroy(&ctx->log_encoder);

    /* Remove msgpack buffer and destroy context */
    flb_upstream_destroy(ctx->u);
    flb_free(ctx->hostname);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_BOOL, "alert", "false",
      0, FLB_TRUE, offsetof(struct flb_in_health_config, alert),
      "Only generate records when the port is down"
    },
    {
      FLB_CONFIG_MAP_BOOL, "add_host", "false",
      0, FLB_TRUE, offsetof(struct flb_in_health_config, add_host),
      "Append hostname to each record"
    },
    {
      FLB_CONFIG_MAP_BOOL, "add_port", "false",
      0, FLB_TRUE, offsetof(struct flb_in_health_config, add_port),
      "Append port to each record"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_in_health_config, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_in_health_config, interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_health_plugin = {
    .name         = "health",
    .description  = "Check TCP server health",
    .cb_init      = in_health_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_health_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_health_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET|FLB_INPUT_CORO
};
