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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <mpack/mpack.h>
#include <stddef.h>
#include <stdio.h>

#include "fluent-bit/flb_input.h"
#include "fluent-bit/flb_kafka.h"
#include "fluent-bit/flb_mem.h"
#include "in_kafka.h"
#include "rdkafka.h"

static int try_json(mpack_writer_t *writer, rd_kafka_message_t *rkm)
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
    mpack_write_object_bytes(writer, buf, bufsize);
    flb_free(buf);
    return 0;
}

static void process_message(mpack_writer_t *writer,
                            rd_kafka_message_t *rkm)
{
    struct flb_time t;

    mpack_write_tag(writer, mpack_tag_array(2));

    flb_time_get(&t);
    flb_time_append_to_mpack(writer, &t, 0);

    mpack_write_tag(writer, mpack_tag_map(6));

    mpack_write_cstr(writer, "topic");
    if (rkm->rkt) {
        mpack_write_cstr(writer, rd_kafka_topic_name(rkm->rkt));
    }
    else {
        mpack_write_nil(writer);
    }

    mpack_write_cstr(writer, "partition");
    mpack_write_i32(writer, rkm->partition);

    mpack_write_cstr(writer, "offset");
    mpack_write_i64(writer, rkm->offset);

    mpack_write_cstr(writer, "error");
    if (rkm->err) {
        mpack_write_cstr(writer, rd_kafka_message_errstr(rkm));
    }
    else {
        mpack_write_nil(writer);
    }

    mpack_write_cstr(writer, "key");
    if (rkm->key) {
        mpack_write_str(writer, rkm->key, rkm->key_len);
    }
    else {
        mpack_write_nil(writer);
    }

    mpack_write_cstr(writer, "payload");
    if (rkm->payload) {
        if (try_json(writer, rkm)) {
            mpack_write_str(writer, rkm->payload, rkm->len);
        }
    }
    else {
        mpack_write_nil(writer);
    }

    mpack_writer_flush_message(writer);
}

static int in_kafka_collect(struct flb_input_instance *ins,
                            struct flb_config *config, void *in_context)
{
    mpack_writer_t writer;
    char *buf;
    size_t bufsize;
    size_t written = 0;
    struct flb_in_kafka_config *ctx = in_context;

    mpack_writer_init_growable(&writer, &buf, &bufsize);

    if (writer.error == mpack_error_memory) {
        flb_plg_error(ins, "Failed to allocate buffer.");
        return -1;
    }

    while (true) {
        rd_kafka_message_t *rkm = rd_kafka_consumer_poll(ctx->kafka.rk, 1);

        if (!rkm) {
            break;
        }

        flb_plg_debug(ins, "kafka message received");
        process_message(&writer, rkm);
        rd_kafka_message_destroy(rkm);
        rd_kafka_commit(ctx->kafka.rk, NULL, 0);

        if (writer.error == mpack_error_memory) {
            flb_plg_error(ins, "Failed to allocate buffer.");
            return -1;
        }
    }

    written = writer.position - writer.buffer;

    if (written == 0) {
        mpack_writer_destroy(&writer);
        return -1;
    }

    flb_input_log_append(ins, NULL, 0, writer.buffer, written);
    mpack_writer_destroy(&writer);

    return 0;
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
    rd_kafka_resp_err_t err;
    char errstr[512];
    (void) data;

    /* Allocate space for the configuration context */
    ctx = flb_malloc(sizeof(struct flb_in_kafka_config));
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

    kafka_conf = flb_kafka_conf_create(&ctx->kafka, &ins->properties, 1);
    if (!kafka_conf) {
        flb_plg_error(ins, "Could not initialize kafka config object");
        goto init_error;
    }

    ctx->kafka.rk = rd_kafka_new(RD_KAFKA_CONSUMER, kafka_conf, errstr,
            sizeof(errstr));

    /* Create Kafka consumer handle */
    if (!ctx->kafka.rk) {
        flb_plg_error(ins, "Failed to create new consumer: %s", errstr);
        goto init_error;
    }

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

    return 0;

init_error:
    if (kafka_topics) {
        rd_kafka_topic_partition_list_destroy(kafka_topics);
    }
    if (ctx->kafka.rk) {
        rd_kafka_destroy(ctx->kafka.rk);
    }
    else if (kafka_conf) {
        // conf is already destroyed when rd_kafka is initialized
        rd_kafka_conf_destroy(kafka_conf);
    }
    flb_free(ctx);

    return -1;
}

/* Cleanup serial input */
static int in_kafka_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_kafka_config *ctx;

    if (!in_context) {
        return 0;
    }

    ctx = in_context;
    rd_kafka_destroy(ctx->kafka.rk);
    flb_free(ctx->kafka.brokers);
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
    //FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_in_kafka_config, rdkafka_opts),
    0,  FLB_FALSE, 0,
    "Set the librdkafka options"
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
    .cb_exit      = in_kafka_exit,
    .config_map   = config_map
};
