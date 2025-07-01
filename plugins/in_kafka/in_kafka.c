/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/aws/flb_aws_msk_iam.h>

#include <mpack/mpack.h>
#include <stddef.h>
#include <stdio.h>

#include "fluent-bit/flb_input.h"
#include "fluent-bit/flb_kafka.h"
#include "fluent-bit/flb_mem.h"
#include "in_kafka.h"
#include "rdkafka.h"

static int try_json(struct flb_log_event_encoder *log_encoder,
                    rd_kafka_message_t *rkm)
{
    int root_type;
    char *buf = NULL;
    size_t bufsize;
    int ret;

    ret = flb_pack_json(rkm->payload, rkm->len, &buf, &bufsize, &root_type, NULL);
    if (ret) {
        if (buf) {
            flb_free(buf);
        }
        return ret;
    }
    flb_log_event_encoder_append_body_raw_msgpack(log_encoder, buf, bufsize);
    flb_free(buf);
    return 0;
}

static int process_message(struct flb_in_kafka_config *ctx,
                           rd_kafka_message_t *rkm)
{
    struct flb_log_event_encoder *log_encoder = ctx->log_encoder;
    int ret;

    ret = flb_log_event_encoder_begin_record(log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "topic");
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        if (rkm->rkt) {
            ret = flb_log_event_encoder_append_body_cstring(log_encoder,
                                                            (char *) rd_kafka_topic_name(rkm->rkt));
        }
        else {
            ret = flb_log_event_encoder_append_body_null(log_encoder);
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(log_encoder,
                                                       FLB_LOG_EVENT_CSTRING_VALUE("partition"),
                                                       FLB_LOG_EVENT_INT32_VALUE(rkm->partition));
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(log_encoder,
                                                       FLB_LOG_EVENT_CSTRING_VALUE("offset"),
                                                       FLB_LOG_EVENT_INT64_VALUE(rkm->offset));
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "error");
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        if (rkm->err) {
            ret = flb_log_event_encoder_append_body_cstring(log_encoder,
                                                            (char *) rd_kafka_message_errstr(rkm));
        }
        else {
            ret = flb_log_event_encoder_append_body_null(log_encoder);
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "key");
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        if (rkm->key) {
            ret = flb_log_event_encoder_append_body_string(log_encoder,
                                                           rkm->key,
                                                           rkm->key_len);
        }
        else {
            ret = flb_log_event_encoder_append_body_null(log_encoder);
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "payload");
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        if (rkm->payload) {
            if (ctx->format != FLB_IN_KAFKA_FORMAT_JSON ||
                    try_json(log_encoder, rkm)) {
                ret = flb_log_event_encoder_append_body_string(log_encoder,
                                                               rkm->payload,
                                                               rkm->len);
            }
        }
        else {
            ret = flb_log_event_encoder_append_body_null(log_encoder);
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(log_encoder);
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
    }

    return ret;
}

static int in_kafka_collect(struct flb_input_instance *ins,
                            struct flb_config *config, void *in_context)
{
    int ret;
    struct flb_in_kafka_config *ctx = in_context;
    rd_kafka_message_t *rkm;

    ret = FLB_EVENT_ENCODER_SUCCESS;

    while (ret == FLB_EVENT_ENCODER_SUCCESS) {
        /* Set the Kafka poll timeout based on execution mode:
         *
         * a) Running in the main event loop (non-threaded):
         *    - Use a minimal timeout to avoid blocking other inputs.
         *
         * b) Running in a dedicated thread:
         *    - Optimize for throughput by allowing Kafka's internal batching.
         *    - Align with 'fetch.wait.max.ms' (default: 500ms) to maximize batch efficiency.
         *    - Set timeout slightly higher than 'fetch.wait.max.ms' (e.g., 1.5x - 2x) to
         *      ensure it does not interfere with Kafka's fetch behavior, while still
         *      keeping the consumer responsive.
         */
        if (ctx->ins->flags & FLB_INPUT_THREADED) {
            /* Threaded mode: Optimize for batch processing and efficiency */
            rkm = rd_kafka_consumer_poll(ctx->kafka.rk, ctx->poll_timeout_ms);
        } else {
            /* Main event loop: Minimize delay for non-blocking execution */
            rkm = rd_kafka_consumer_poll(ctx->kafka.rk, 1);
        }

        if (!rkm) {
            break;
        }

        if (rkm->err) {
            flb_plg_warn(ins, "consumer error: %s\n",
                         rd_kafka_message_errstr(rkm));
            rd_kafka_message_destroy(rkm);
            continue;
        }

        flb_plg_debug(ins, "kafka message received");

        ret = process_message(ctx, rkm);

        rd_kafka_message_destroy(rkm);

        /* TO-DO: commit the record based on `ret` */
        rd_kafka_commit(ctx->kafka.rk, NULL, 0);

        /* Break from the loop when reaching the limit of polling if available */
        if (ctx->polling_threshold != FLB_IN_KAFKA_UNLIMITED &&
            ctx->log_encoder->output_length > ctx->polling_threshold + 512) {
            break;
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        if (ctx->log_encoder->output_length > 0) {
            flb_input_log_append(ins, NULL, 0,
                                 ctx->log_encoder->output_buffer,
                                 ctx->log_encoder->output_length);
        }
        ret = 0;
    }
    else {
        flb_plg_error(ins, "Error encoding record : %d", ret);
        ret = -1;
    }

    flb_log_event_encoder_reset(ctx->log_encoder);

    return ret;
}

/* Initialize plugin */
static int in_kafka_init(struct flb_input_instance *ins,
                         struct flb_config *config, void *data)
{
    int ret;
    const char *conf;
    struct flb_in_kafka_config *ctx;
    rd_kafka_conf_t *kafka_conf = NULL;
    rd_kafka_topic_partition_list_t *kafka_topics = NULL;
    rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;
    rd_kafka_conf_res_t res;
    char errstr[512];
    (void) data;
    char conf_val[16];

    /* Allocate space for the configuration context */
    ctx = flb_calloc(1, sizeof(struct flb_in_kafka_config));
    if (!ctx) {
        return -1;
    }
    ctx->ins = ins;

    ret = flb_input_config_map_set(ins, (void*) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration.");
        flb_free(ctx);
        return -1;
    }

    /* Retrieve SASL mechanism if configured */
    conf = flb_input_get_property("rdkafka.sasl.mechanism", ins);
    if (conf) {
        ctx->sasl_mechanism = flb_sds_create(conf);
        flb_plg_info(ins, "SASL mechanism configured: %s", ctx->sasl_mechanism);
    }

    kafka_conf = flb_kafka_conf_create(&ctx->kafka, &ins->properties, 1);
    if (!kafka_conf) {
        flb_plg_error(ins, "Could not initialize kafka config object");
        goto init_error;
    }

    if (ctx->buffer_max_size > 0) {
        ctx->polling_threshold = ctx->buffer_max_size;

        snprintf(conf_val, sizeof(conf_val), "%zu", ctx->polling_threshold - 512);
        res = rd_kafka_conf_set(kafka_conf, "fetch.max.bytes", conf_val,
                                errstr, sizeof(errstr));
        if (res != RD_KAFKA_CONF_OK) {
            flb_plg_error(ins, "Failed to set up fetch.max.bytes: %s, val = %s",
                          rd_kafka_err2str(err), conf_val);
            goto init_error;
        }

        snprintf(conf_val, sizeof(conf_val), "%zu", ctx->polling_threshold);
        res = rd_kafka_conf_set(kafka_conf, "receive.message.max.bytes", conf_val,
                                errstr, sizeof(errstr));
        if (res != RD_KAFKA_CONF_OK) {
            flb_plg_error(ins, "Failed to set up receive.message.max.bytes: %s, val = %s",
                          rd_kafka_err2str(err), conf_val);
            goto init_error;
        }
    }
    else {
        ctx->polling_threshold = FLB_IN_KAFKA_UNLIMITED;
    }

    if (ctx->aws_msk_iam && ctx->aws_msk_iam_cluster_arn && ctx->sasl_mechanism &&
        strcasecmp(ctx->sasl_mechanism, "OAUTHBEARER") == 0) {
        flb_plg_info(ins, "registering MSK IAM authentication with cluster ARN: %s",
                     ctx->aws_msk_iam_cluster_arn);
        ctx->msk_iam = flb_aws_msk_iam_register_oauth_cb(config,
                                                         kafka_conf,
                                                         ctx->aws_msk_iam_cluster_arn,
                                                         ctx);
        if (!ctx->msk_iam) {
            flb_plg_error(ins, "failed to setup MSK IAM authentication");
        }
        else {
            res = rd_kafka_conf_set(kafka_conf, "sasl.oauthbearer.config",
                                    "principal=admin", errstr, sizeof(errstr));
            if (res != RD_KAFKA_CONF_OK) {
                flb_plg_error(ins,
                             "failed to set sasl.oauthbearer.config: %s",
                             errstr);
            }
        }
    }
    ctx->kafka.rk = rd_kafka_new(RD_KAFKA_CONSUMER, kafka_conf, errstr, sizeof(errstr));

    /* Create Kafka consumer handle */
    if (!ctx->kafka.rk) {
        flb_plg_error(ins, "Failed to create new consumer: %s", errstr);
        goto init_error;
    }

    /* Trigger initial token refresh for OAUTHBEARER */
    rd_kafka_poll(ctx->kafka.rk, 0);

    conf = flb_input_get_property("topics", ins);
    if (!conf) {
        flb_plg_error(ins, "config: no topics specified");
        goto init_error;
    }

    kafka_topics = flb_kafka_parse_topics(conf);
    if (!kafka_topics) {
        flb_plg_error(ins, "Failed to parse topic list");
        goto init_error;
    }

    if (strcasecmp(ctx->format_str, "none") == 0) {
        ctx->format = FLB_IN_KAFKA_FORMAT_NONE;
    }
    else if (strcasecmp(ctx->format_str, "json") == 0) {
        ctx->format = FLB_IN_KAFKA_FORMAT_JSON;
    }
    else {
        flb_plg_error(ins, "config: invalid format \"%s\"", ctx->format_str);
        goto init_error;
    }

    if ((err = rd_kafka_subscribe(ctx->kafka.rk, kafka_topics))) {
        flb_plg_error(ins, "Failed to start consuming topics: %s", rd_kafka_err2str(err));
        goto init_error;
    }
    rd_kafka_topic_partition_list_destroy(kafka_topics);
    kafka_topics = NULL;

    /* Set the context */
    flb_input_set_context(ins, ctx);
    /* Collect upon data available on the pipe read fd */

    int poll_seconds = ctx->poll_ms / 1000;
    int poll_milliseconds = ctx->poll_ms % 1000;

    ret = flb_input_set_collector_time(ins,
                                       in_kafka_collect,
                                       poll_seconds, poll_milliseconds * 1e6,
                                       config);
    if (ret) {
        flb_plg_error(ctx->ins, "could not set collector for kafka input plugin");
        goto init_error;
    }

    ctx->coll_fd = ret;

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(ins, "could not initialize log encoder");
        goto init_error;
    }

    return 0;

init_error:
    if (kafka_topics) {
        rd_kafka_topic_partition_list_destroy(kafka_topics);
    }
    if (ctx->kafka.rk) {
        struct flb_msk_iam_cb *cb;

        cb = rd_kafka_opaque(ctx->kafka.rk);
        rd_kafka_destroy(ctx->kafka.rk);
        if (cb) {
            flb_free(cb);
        }
    }
    else if (kafka_conf) {
        /* conf is already destroyed when rd_kafka is initialized */
        rd_kafka_conf_destroy(kafka_conf);
    }
    flb_sds_destroy(ctx->sasl_mechanism);
    flb_free(ctx);

    return -1;
}

static void in_kafka_pause(void *data, struct flb_config *config)
{
    struct flb_in_kafka_config *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_kafka_resume(void *data, struct flb_config *config)
{
    struct flb_in_kafka_config *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

/* Cleanup serial input */
static int in_kafka_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_kafka_config *ctx;
    struct flb_aws_msk_iam *msk_iam;

    if (!in_context) {
        return 0;
    }

    ctx = in_context;
    if (ctx->kafka.rk) {
        msk_iam = rd_kafka_opaque(ctx->kafka.rk);
        rd_kafka_destroy(ctx->kafka.rk);
        if (msk_iam) {
            flb_aws_msk_iam_destroy(msk_iam);
        }
    }
    flb_free(ctx->kafka.brokers);

    if (ctx->log_encoder){
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    flb_sds_destroy(ctx->sasl_mechanism);

    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
   {
    FLB_CONFIG_MAP_INT, "poll_ms", FLB_IN_KAFKA_DEFAULT_POLL_MS,
    0, FLB_TRUE, offsetof(struct flb_in_kafka_config, poll_ms),
    "Interval in milliseconds to check for new messages."
   },
   {
    FLB_CONFIG_MAP_STR, "topics", (char *)NULL,
    0, FLB_FALSE, 0,
    "Set the kafka topics, delimited by commas."
   },
   {
    FLB_CONFIG_MAP_STR, "format", FLB_IN_KAFKA_DEFAULT_FORMAT,
    0, FLB_TRUE, offsetof(struct flb_in_kafka_config, format_str),
    "Set the data format which will be used for parsing records."
   },
   {
    FLB_CONFIG_MAP_STR, "brokers", (char *)NULL,
    0, FLB_FALSE, 0,
    "Set the kafka brokers, delimited by commas."
   },
   {
    FLB_CONFIG_MAP_STR, "client_id", (char *)NULL,
    0, FLB_FALSE, 0,
    "Set the kafka client_id."
   },
   {
    FLB_CONFIG_MAP_STR, "group_id", (char *)NULL,
    0, FLB_FALSE, 0,
    "Set the kafka group_id."
   },
   {
    FLB_CONFIG_MAP_STR_PREFIX, "rdkafka.", NULL,
    /* FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_in_kafka_config, rdkafka_opts), */
    0,  FLB_FALSE, 0,
    "Set the librdkafka options"
   },
   {
    FLB_CONFIG_MAP_SIZE, "buffer_max_size", FLB_IN_KAFKA_BUFFER_MAX_SIZE,
    0, FLB_TRUE, offsetof(struct flb_in_kafka_config, buffer_max_size),
    "Set the maximum size of chunk"
   },
   {
   FLB_CONFIG_MAP_INT, "poll_timeout_ms", "1",
   0, FLB_TRUE, offsetof(struct flb_in_kafka_config, poll_timeout_ms),
   "Set the timeout in milliseconds for Kafka consumer poll operations. "
   "This option only takes effect when running in a dedicated thread (i.e., when 'threaded' is enabled). "
   "Using a higher timeout (e.g., 1.5x - 2x 'rdkafka.fetch.wait.max.ms') "
   "can improve efficiency by leveraging Kafka's batching mechanism."
  },
  {
   FLB_CONFIG_MAP_STR, "aws_msk_iam_cluster_arn", (char *)NULL,
   0, FLB_TRUE, offsetof(struct flb_in_kafka_config, aws_msk_iam_cluster_arn),
   "ARN of the MSK cluster when using AWS IAM authentication"
  },
  {
    FLB_CONFIG_MAP_BOOL, "aws_msk_iam", "false",
    0, FLB_TRUE, offsetof(struct flb_in_kafka_config, aws_msk_iam),
    "Enable AWS MSK IAM authentication"
  },
  /* EOF */
  {0}
};

/* Plugin reference */
struct flb_input_plugin in_kafka_plugin = {
    .name         = "kafka",
    .description  = "Kafka consumer input plugin",
    .cb_init      = in_kafka_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_kafka_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_kafka_pause,
    .cb_resume    = in_kafka_resume,
    .cb_exit      = in_kafka_exit,
    .config_map   = config_map
};
