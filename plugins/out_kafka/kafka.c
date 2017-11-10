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
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>

#include "kafka_config.h"

static void dr_msg_cb (rd_kafka_t *rk,
                       const rd_kafka_message_t *rkmessage, void *opaque) {
        if (rkmessage->err)
                fprintf(stderr, "%% Message delivery failed: %s\n",
                        rd_kafka_err2str(rkmessage->err));
        else
                fprintf(stderr,
                        "%% Message delivered (%zd bytes, "
                        "partition %"PRId32")\n",
                        rkmessage->len, rkmessage->partition);

        /* The rkmessage is destroyed automatically by librdkafka */
}

static int cb_kafka_init(struct flb_output_instance *ins,
                         struct flb_config *config,
                         void *data)
{
    struct flb_kafka *ctx;

    /* Configuration */
    ctx = flb_kafka_conf_create(ins, config);
    if (!ctx) {
        flb_error("[out_kafka] failed to initialize");
        return -1;
    }

    /* Kafka Callback for messages delivery */
    rd_kafka_conf_set_dr_msg_cb(ctx->conf, dr_msg_cb);

    /* Set global context */
    flb_output_set_context(ins, ctx);
    return 0;
}

int produce_message(struct flb_time *tm, msgpack_object *map,
                    struct flb_kafka *ctx)
{
    int i;
    int ret;
    int size;
    char *json_buf;
    size_t json_size;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_object key;
    msgpack_object val;

    /* Init temporal buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Make room for the timestamp */
    size = map->via.map.size + 1;
    msgpack_pack_map(&mp_pck, size);

    /* Pack timestamp */
    msgpack_pack_str(&mp_pck, ctx->timestamp_key_len);
    msgpack_pack_str_body(&mp_pck,
                          ctx->timestamp_key, ctx->timestamp_key_len);
    msgpack_pack_double(&mp_pck, flb_time_to_double(tm));

    for (i = 0; i < map->via.map.size; i++) {
        key = map->via.map.ptr[i].key;
        val = map->via.map.ptr[i].val;

        msgpack_pack_object(&mp_pck, key);
        msgpack_pack_object(&mp_pck, val);
    }

    ret = flb_msgpack_raw_to_json_str(mp_sbuf.data, mp_sbuf.size,
                                      &json_buf, &json_size);
    printf("=>%s\n", json_buf);
    if (ret != 0) {
        flb_error("[out_kafka] error encoding to JSON");
        msgpack_sbuffer_destroy(&mp_sbuf);
        return -1;
    }

    ret = rd_kafka_produce(ctx->topic,
                           RD_KAFKA_PARTITION_UA,
                           RD_KAFKA_MSG_F_COPY,
                           json_buf, json_size,
                           NULL, 0,
                           NULL);
    if (ret == -1) {
        fprintf(stderr,
                "%% Failed to produce to topic %s: %s\n",
                rd_kafka_topic_name(ctx->topic),
                rd_kafka_err2str(rd_kafka_last_error()));

    }
    else {
        rd_kafka_poll(ctx->producer, 1);
    }
    flb_free(json_buf);
    msgpack_sbuffer_destroy(&mp_sbuf);
    return 0;
}

static void cb_kafka_flush(void *data, size_t bytes,
                           char *tag, int tag_len,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{

    int ret;
    size_t off = 0;
    struct flb_kafka *ctx = out_context;
    struct flb_time tms;
    msgpack_object *obj;
    msgpack_unpacked result;

    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        ret = produce_message(&tms, obj, ctx);
        if (ret == FLB_ERROR) {
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_kafka_exit(void *data, struct flb_config *config)
{
    struct flb_kafka *ctx = data;

    flb_kafka_conf_destroy(ctx);
    return 0;
}

struct flb_output_plugin out_kafka_plugin = {
    .name         = "kafka",
    .description  = "Kafka",
    .cb_init      = cb_kafka_init,
    .cb_flush     = cb_kafka_flush,
    .cb_exit      = cb_kafka_exit,
    .flags        = 0
};
