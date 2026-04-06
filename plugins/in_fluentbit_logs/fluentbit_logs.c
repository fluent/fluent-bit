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
#include <fluent-bit/flb_log_event_encoder.h>

struct flb_in_fluentbit_logs {
    int coll_fd;
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *log_encoder;
};

static const char *record_type_to_level(int type)
{
    switch (type) {
    case FLB_LOG_ERROR:
        return "error";
    case FLB_LOG_WARN:
        return "warn";
    case FLB_LOG_INFO:
        return "info";
    case FLB_LOG_DEBUG:
    case FLB_LOG_IDEBUG:
        return "debug";
    case FLB_LOG_TRACE:
        return "trace";
    case FLB_LOG_HELP:
        return "help";
    default:
        return "unknown";
    }
}

static int flush_mirrored_records(struct flb_in_fluentbit_logs *ctx)
{
    int ret;
    const char *level;
    struct flb_time timestamp;
    struct flb_log_record *record;

    record = flb_log_pipeline_dequeue(ctx->ins->config);

    while (record != NULL) {
        ret = flb_log_event_encoder_begin_record(ctx->log_encoder);
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            timestamp.tm.tv_sec = record->timestamp_sec;
            timestamp.tm.tv_nsec = record->timestamp_nsec;
            ret = flb_log_event_encoder_set_timestamp(ctx->log_encoder, &timestamp);
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            level = record_type_to_level(record->type);
            ret = flb_log_event_encoder_append_body_values(
                      ctx->log_encoder,
                      FLB_LOG_EVENT_CSTRING_VALUE("level"),
                      FLB_LOG_EVENT_CSTRING_VALUE(level),
                      FLB_LOG_EVENT_CSTRING_VALUE("message"),
                      FLB_LOG_EVENT_STRING_VALUE(record->msg, record->size));
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
        }

        flb_log_record_destroy(record);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins, "could not encode mirrored log record");
            flb_log_event_encoder_reset(ctx->log_encoder);
            return -1;
        }

        record = flb_log_pipeline_dequeue(ctx->ins->config);
    }

    if (ctx->log_encoder->output_length > 0) {
        ret = flb_input_log_append(ctx->ins, NULL, 0,
                                   ctx->log_encoder->output_buffer,
                                   ctx->log_encoder->output_length);
        flb_log_event_encoder_reset(ctx->log_encoder);
        return ret;
    }

    return 0;
}

static int cb_fluentbit_logs_collect(struct flb_input_instance *ins,
                                     struct flb_config *config, void *in_context)
{
    int ret;
    char buffer[256];
    struct flb_in_fluentbit_logs *ctx = in_context;

    (void) ins;
    (void) config;

    do {
        ret = flb_pipe_r(flb_log_pipeline_get_event_fd(ctx->ins->config),
                         buffer, sizeof(buffer));
    } while (ret > 0);

    return flush_mirrored_records(ctx);
}

static int in_fluentbit_logs_init(struct flb_input_instance *in,
                                  struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_fluentbit_logs *ctx;

    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_in_fluentbit_logs));
    if (ctx == NULL) {
        flb_errno();
        return -1;
    }

    ctx->ins = in;
    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ctx->log_encoder == NULL) {
        flb_plg_error(in, "could not initialize event encoder");
        flb_free(ctx);
        return -1;
    }

    ret = flb_log_pipeline_enable(config);
    if (ret != 0) {
        flb_plg_error(in, "could not enable mirrored logger pipeline");
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    flb_input_set_context(in, ctx);

    ret = flb_input_set_collector_event(in,
                                        cb_fluentbit_logs_collect,
                                        flb_log_pipeline_get_event_fd(config),
                                        config);
    if (ret < 0) {
        flb_plg_error(in, "could not register mirrored logger collector");
        flb_log_pipeline_disable(config);
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    ctx->coll_fd = ret;

    return 0;
}

static int in_fluentbit_logs_exit(void *data, struct flb_config *config)
{
    struct flb_in_fluentbit_logs *ctx = data;

    if (ctx == NULL) {
        return 0;
    }

    flb_log_pipeline_disable(config);

    if (ctx->log_encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    flb_free(ctx);

    return 0;
}

static void in_fluentbit_logs_pause(void *data, struct flb_config *config)
{
    struct flb_in_fluentbit_logs *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_fluentbit_logs_resume(void *data, struct flb_config *config)
{
    struct flb_in_fluentbit_logs *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

struct flb_input_plugin in_fluentbit_logs_plugin = {
    .name         = "fluentbit_logs",
    .description  = "Fluent Bit internal logs",
    .cb_init      = in_fluentbit_logs_init,
    .cb_pre_run   = NULL,
    .cb_flush_buf = NULL,
    .config_map   = NULL,
    .cb_pause     = in_fluentbit_logs_pause,
    .cb_resume    = in_fluentbit_logs_resume,
    .cb_exit      = in_fluentbit_logs_exit,
};
