/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_mem.h>

#include "kafka_config.h"

struct flb_kafka *flb_kafka_conf_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    char *tmp;
    char errstr[512];
    struct flb_kafka *ctx;

    /* Configuration context */
    ctx = flb_calloc(1, sizeof(struct flb_kafka));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* rdkafka config context */
    ctx->conf = rd_kafka_conf_new();
    if (!ctx->conf) {
        flb_error("[out_kafka] error creating context");
        flb_free(ctx);
        return NULL;
    }

    /* Config: Brokers */
    tmp = flb_output_get_property("brokers", ins);
    if (tmp) {
        ret = rd_kafka_conf_set(ctx->conf,
                                "bootstrap.servers",
                                tmp,
                                errstr, sizeof(errstr));
        if (ret != RD_KAFKA_CONF_OK) {
            flb_error("[out_kafka] config: %s", errstr);
            flb_free(ctx);
            return NULL;
        }
        ctx->brokers = flb_strdup(tmp);
    }
    else {
        flb_error("[out_kafka] config: no brokers defined");
        flb_free(ctx);
        return NULL;
    }

    rd_kafka_conf_set(ctx->conf, "queue.buffering.max.ms", "1",
                      errstr, sizeof(errstr));
    rd_kafka_conf_set(ctx->conf, "batch.num.messages", "1", errstr, sizeof(errstr));
    /* Config: Timestamp_Key */
    tmp = flb_output_get_property("timestamp_key", ins);
    if (tmp) {
        ctx->timestamp_key = flb_strdup(tmp);
        ctx->timestamp_key_len = strlen(tmp);
    }
    else {
        ctx->timestamp_key = FLB_KAFKA_TS_KEY;
        ctx->timestamp_key_len = strlen(FLB_KAFKA_TS_KEY);
    }

    /* Kafka Producer */
    ctx->producer = rd_kafka_new(RD_KAFKA_PRODUCER, ctx->conf,
                                 errstr, sizeof(errstr));
    if (!ctx->producer) {
        flb_error("[out_kafka] failed to create producer: %s",
                  errstr);
        flb_kafka_conf_destroy(ctx);
        return NULL;
    }

    /* Config: Topic */
    tmp = flb_output_get_property("topic", ins);
    if (!tmp) {
        tmp = FLB_KAFKA_TOPIC;
    }
    ctx->topic = rd_kafka_topic_new(ctx->producer, tmp, NULL);
    if (!ctx->topic) {
        flb_error("[out_kafka] failed to create topic: %s",
                  rd_kafka_err2str(rd_kafka_last_error()));
        flb_kafka_conf_destroy(ctx);
        return NULL;
    }

    return ctx;
}

int flb_kafka_conf_destroy(struct flb_kafka *ctx)
{
    if (!ctx) {
        return 0;
    }

    if (ctx->brokers) {
        flb_free(ctx->brokers);
    }
    if (ctx->topic) {
        rd_kafka_topic_destroy(ctx->topic);
    }
    if (ctx->producer) {
        rd_kafka_destroy(ctx->producer);
    }

    flb_free(ctx);
    return 0;
}
