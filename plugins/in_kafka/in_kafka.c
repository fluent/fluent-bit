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
#include <fluent-bit/flb_input_thread.h>
#include <mpack/mpack.h>
#include <stddef.h>
#include <stdio.h>

#include "fluent-bit/flb_input.h"
#include "fluent-bit/flb_kafka.h"
#include "in_kafka.h"
#include "rdkafka.h"

static int try_json(mpack_writer_t *writer, rd_kafka_message_t *rkm)
{
    int root_type;
    char *buf = NULL;
    size_t bufsize;
    int ret;

    ret = flb_pack_json(rkm->payload, rkm->len, &buf, &bufsize, &root_type);
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
    } else {
        mpack_write_nil(writer);
    }

    mpack_write_cstr(writer, "partition");
    mpack_write_i32(writer, rkm->partition);

    mpack_write_cstr(writer, "offset");
    mpack_write_i64(writer, rkm->offset);

    mpack_write_cstr(writer, "error");
    if (rkm->err) {
        mpack_write_cstr(writer, rd_kafka_message_errstr(rkm));
    } else {
        mpack_write_nil(writer);
    }

    mpack_write_cstr(writer, "key");
    if (rkm->key) {
        mpack_write_str(writer, rkm->key, rkm->key_len);
    } else {
        mpack_write_nil(writer);
    }

    mpack_write_cstr(writer, "payload");
    if (rkm->payload) {
        if (try_json(writer, rkm)) {
            mpack_write_str(writer, rkm->payload, rkm->len);
        }
    } else {
        mpack_write_nil(writer);
    }

    mpack_writer_flush_message(writer);
}

static void in_kafka_callback(int write_fd, void *data)
{
    struct flb_input_thread *it = data;
    struct flb_in_kafka_config *ctx = data - offsetof(struct flb_in_kafka_config, it);
    mpack_writer_t *writer = &ctx->it.writer;

    while (!flb_input_thread_exited(it)) {
        rd_kafka_message_t *rkm = rd_kafka_consumer_poll(ctx->kafka.rk, 500);

        if (rkm) {
            process_message(writer, rkm);
            fflush(ctx->it.write_file);
            rd_kafka_message_destroy(rkm);
            rd_kafka_commit(ctx->kafka.rk, NULL, 0);
        }
    }
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

    /* create worker thread */
    ret = flb_input_thread_init(&ctx->it, in_kafka_callback, &ctx->it);
    if (ret) {
        flb_errno();
        flb_plg_error(ins, "Could not initialize worker thread");
        goto init_error;
    }

    /* Set the context */
    flb_input_set_context(ins, &ctx->it);

    /* Collect upon data available on the pipe read fd */
    ret = flb_input_set_collector_event(ins,
                                        flb_input_thread_collect,
                                        ctx->it.read,
                                        config);
    if (ret == -1) {
        flb_plg_error(ins, "Could not set collector for thread dummy input plugin");
        goto init_error;
    }
    ctx->it.coll_fd = ret;

    return 0;

init_error:
    if (kafka_topics) {
        rd_kafka_topic_partition_list_destroy(kafka_topics);
    }
    if (ctx->kafka.rk) {
        rd_kafka_destroy(ctx->kafka.rk);
    } else if (kafka_conf) {
        // conf is already destroyed when rd_kafka is initialized
        rd_kafka_conf_destroy(kafka_conf);
    }
    flb_free(ctx);

    return -1;
}

/* Cleanup serial input */
static int in_kafka_exit(void *in_context, struct flb_config *config)
{
    struct flb_input_thread *it;
    struct flb_in_kafka_config *ctx;

    if (!in_context) {
        return 0;
    }

    it = in_context;
    ctx = (in_context - offsetof(struct flb_in_kafka_config, it));
    flb_input_thread_destroy(it, ctx->ins);
    rd_kafka_destroy(ctx->kafka.rk);
    flb_free(ctx->kafka.brokers);
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_kafka_plugin = {
    .name         = "kafka",
    .description  = "Kafka consumer input plugin",
    .cb_init      = in_kafka_init,
    .cb_pre_run   = NULL,
    .cb_collect   = flb_input_thread_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_kafka_exit
};
