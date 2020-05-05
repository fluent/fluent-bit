/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>

#include "kafka_config.h"
#include "kafka_topic.h"

void cb_kafka_msg(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage,
                  void *opaque)
{
    struct flb_kafka *ctx = (struct flb_kafka *) opaque;

    if (rkmessage->err) {
        flb_plg_warn(ctx->ins, "message delivery failed: %s",
                     rd_kafka_err2str(rkmessage->err));
    }
    else {
        flb_plg_debug(ctx->ins, "message delivered (%zd bytes, "
                      "partition %"PRId32")",
                      rkmessage->len, rkmessage->partition);
    }
}

void cb_kafka_logger(const rd_kafka_t *rk, int level,
                     const char *fac, const char *buf)
{
    struct flb_kafka *ctx;

    ctx = (struct flb_kafka *) rd_kafka_opaque(rk);

    if (level <= FLB_KAFKA_LOG_ERR) {
        flb_plg_error(ctx->ins, "%s: %s",
                      rk ? rd_kafka_name(rk) : NULL, buf);
    }
    else if (level == FLB_KAFKA_LOG_WARNING) {
        flb_plg_warn(ctx->ins, "%s: %s",
                     rk ? rd_kafka_name(rk) : NULL, buf);
    }
    else if (level == FLB_KAFKA_LOG_NOTICE || level == FLB_KAFKA_LOG_INFO) {
        flb_plg_info(ctx->ins, "%s: %s",
                     rk ? rd_kafka_name(rk) : NULL, buf);
    }
    else if (level == FLB_KAFKA_LOG_DEBUG) {
        flb_plg_debug(ctx->ins, "%s: %s",
                      rk ? rd_kafka_name(rk) : NULL, buf);
    }
}

static int cb_kafka_init(struct flb_output_instance *ins,
                         struct flb_config *config,
                         void *data)
{
    struct flb_kafka *ctx;

    /* Configuration */
    ctx = flb_kafka_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "failed to initialize");
        return -1;
    }

    /* Set global context */
    flb_output_set_context(ins, ctx);
    return 0;
}

int produce_message(struct flb_time *tm, msgpack_object *map,
                    struct flb_kafka *ctx, struct flb_config *config)
{
    int i;
    int ret;
    int size;
    int queue_full_retries = 0;
    char *out_buf;
    size_t out_size;
    struct mk_list *head;
    struct mk_list *topics;
    struct flb_split_entry *entry;
    char *dynamic_topic;
    char *message_key = NULL;
    size_t message_key_len = 0;
    struct flb_kafka_topic *topic = NULL;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_object key;
    msgpack_object val;
    flb_sds_t s;

    /* Init temporal buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    if (ctx->format == FLB_KAFKA_FMT_JSON || ctx->format == FLB_KAFKA_FMT_MSGP) {
        /* Make room for the timestamp */
        size = map->via.map.size + 1;
        msgpack_pack_map(&mp_pck, size);

        /* Pack timestamp */
        msgpack_pack_str(&mp_pck, ctx->timestamp_key_len);
        msgpack_pack_str_body(&mp_pck,
                              ctx->timestamp_key, ctx->timestamp_key_len);
        switch (ctx->timestamp_format) {
            case FLB_JSON_DATE_DOUBLE:
                msgpack_pack_double(&mp_pck, flb_time_to_double(tm));
                break;

            case FLB_JSON_DATE_ISO8601:
                {
                size_t date_len;
                int len;
                struct tm _tm;
                char time_formatted[32];
                /* Format the time; use microsecond precision (not nanoseconds). */
                gmtime_r(&tm->tm.tv_sec, &_tm);
                date_len = strftime(time_formatted, sizeof(time_formatted) - 1,
                             FLB_JSON_DATE_ISO8601_FMT, &_tm);

                len = snprintf(time_formatted + date_len, sizeof(time_formatted) - 1 - date_len,
                               ".%06" PRIu64 "Z", (uint64_t) tm->tm.tv_nsec / 1000);
                date_len += len;

                msgpack_pack_str(&mp_pck, date_len);
                msgpack_pack_str_body(&mp_pck, time_formatted, date_len);
                }
                break;
        }
    }
    else {
        size = map->via.map.size;
        msgpack_pack_map(&mp_pck, size);
    }

    for (i = 0; i < map->via.map.size; i++) {
        key = map->via.map.ptr[i].key;
        val = map->via.map.ptr[i].val;

        msgpack_pack_object(&mp_pck, key);
        msgpack_pack_object(&mp_pck, val);

        /* Lookup message key */
        if (ctx->message_key_field && !message_key && val.type == MSGPACK_OBJECT_STR) {
            if (key.via.str.size == ctx->message_key_field_len &&
                    strncmp(key.via.str.ptr, ctx->message_key_field, ctx->message_key_field_len) == 0) {
                message_key = (char *) val.via.str.ptr;
                message_key_len = val.via.str.size;
            }
        }

        /* Lookup key/topic */
        if (ctx->topic_key && !topic && val.type == MSGPACK_OBJECT_STR) {
            if (key.via.str.size == ctx->topic_key_len &&
                strncmp(key.via.str.ptr, ctx->topic_key, ctx->topic_key_len) == 0) {
                topic = flb_kafka_topic_lookup((char *) val.via.str.ptr,
                                               val.via.str.size, ctx);
                /* Add extracted topic on the fly to topiclist */
                if (ctx->dynamic_topic) {
                    /* Only if default topic is set and this topicname is not set for this message */
                    if (strncmp(topic->name, flb_kafka_topic_default(ctx)->name, val.via.str.size) == 0 &&
                        (strncmp(topic->name, val.via.str.ptr, val.via.str.size) != 0) ) {
                        if (strstr(val.via.str.ptr, ",")) {
                            /* Don't allow commas in kafkatopic name */
                            flb_warn("',' not allowed in dynamic_kafka topic names");
                            continue;
                        }
                        if (val.via.str.size > 64) {
                            /* Don't allow length of dynamic kafka topics > 64 */
                            flb_warn(" dynamic kafka topic length > 64 not allowed");
                            continue;
                        }
                        dynamic_topic = flb_malloc(val.via.str.size + 1);
                        if (!dynamic_topic) {
                            /* Use default topic */
                            flb_errno();
                            continue;
                        }
                        strncpy(dynamic_topic, val.via.str.ptr, val.via.str.size);
                        dynamic_topic[val.via.str.size] = '\0';
                        topics = flb_utils_split(dynamic_topic, ',', 0);
                        if (!topics) {
                            /* Use the default topic */
                            flb_errno();
                            flb_free(dynamic_topic);
                            continue;
                        }
                        mk_list_foreach(head, topics) {
                            /* Add the (one) found topicname to the topic configuration */
                            entry = mk_list_entry(head, struct flb_split_entry, _head);
                            topic = flb_kafka_topic_create(entry->value, ctx);
                            if (!topic) {
                                /* Use default topic  */
                                flb_error("[out_kafka] cannot register topic '%s'",
                                          entry->value);
                                topic = flb_kafka_topic_lookup((char *) val.via.str.ptr,
                                                               val.via.str.size, ctx);
                            }
                            else {
                                flb_info("[out_kafka] new topic added: %s", dynamic_topic);
                            }
                        }
                        flb_free(dynamic_topic);
                    }
                }
            }
        }
    }

    if (ctx->format == FLB_KAFKA_FMT_JSON) {
        s = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
        if (!s) {
            flb_plg_error(ctx->ins, "error encoding to JSON");
            msgpack_sbuffer_destroy(&mp_sbuf);
            return FLB_ERROR;
        }
        out_buf  = s;
        out_size = flb_sds_len(out_buf);
    }
    else if (ctx->format == FLB_KAFKA_FMT_MSGP) {
        out_buf = mp_sbuf.data;
        out_size = mp_sbuf.size;
    }
    else if (ctx->format == FLB_KAFKA_FMT_GELF) {
        s = flb_msgpack_raw_to_gelf(mp_sbuf.data, mp_sbuf.size,
                                    tm, &(ctx->gelf_fields));
        if (s == NULL) {
            flb_plg_error(ctx->ins, "error encoding to GELF");
            msgpack_sbuffer_destroy(&mp_sbuf);
            return FLB_ERROR;
        }
        out_buf = s;
        out_size = flb_sds_len(s);
    }

    if (!message_key) {
        message_key = ctx->message_key;
        message_key_len = ctx->message_key_len;
    }

    if (!topic) {
        topic = flb_kafka_topic_default(ctx);
    }
    if (!topic) {
        flb_plg_error(ctx->ins, "no default topic found");
        msgpack_sbuffer_destroy(&mp_sbuf);
        return FLB_ERROR;
    }

 retry:
    if (queue_full_retries >= 10) {
        if (ctx->format == FLB_KAFKA_FMT_JSON) {
            flb_free(out_buf);
        }
        if (ctx->format == FLB_KAFKA_FMT_GELF) {
            flb_sds_destroy(s);
        }
        msgpack_sbuffer_destroy(&mp_sbuf);
        return FLB_RETRY;
    }

    ret = rd_kafka_produce(topic->tp,
                           RD_KAFKA_PARTITION_UA,
                           RD_KAFKA_MSG_F_COPY,
                           out_buf, out_size,
                           message_key, message_key_len,
                           ctx);
    if (ret == -1) {
        fprintf(stderr,
                "%% Failed to produce to topic %s: %s\n",
                rd_kafka_topic_name(topic->tp),
                rd_kafka_err2str(rd_kafka_last_error()));

        /*
         * rdkafka queue is full, keep trying 'locally' for a few seconds,
         * otherwise let the caller to issue a main retry againt the engine.
         */
        if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
            flb_plg_warn(ctx->ins, "internal queue is full, "
                         "retrying in one second");

            /*
             * If the queue is full, first make sure to discard any further
             * flush request from the engine. This means 'the caller will
             * issue a retry at a later time'.
             */
            ctx->blocked = FLB_TRUE;

            /*
             * Next step is to give it some time to the background rdkafka
             * library to do it own work. By default rdkafka wait 1 second
             * or up to 10000 messages to be enqueued before delivery.
             *
             * If the kafka broker is down we should try a couple of times
             * to enqueue this message, if we exceed 10 times, we just
             * issue a full retry of the data chunk.
             */
            flb_time_sleep(1000, config);
            rd_kafka_poll(ctx->producer, 0);

            /* Issue a re-try */
            queue_full_retries++;
            goto retry;
        }
    }
    else {
        flb_plg_debug(ctx->ins, "enqueued message (%zd bytes) for topic '%s'",
                      out_size, rd_kafka_topic_name(topic->tp));
    }
    ctx->blocked = FLB_FALSE;

    rd_kafka_poll(ctx->producer, 0);
    if (ctx->format == FLB_KAFKA_FMT_JSON) {
        flb_sds_destroy(s);
    }
    if (ctx->format == FLB_KAFKA_FMT_GELF) {
        flb_sds_destroy(s);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    return FLB_OK;
}

static void cb_kafka_flush(const void *data, size_t bytes,
                           const char *tag, int tag_len,
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

    /*
     * If the context is blocked, means rdkafka queue is full and no more
     * messages can be appended. For our called (Fluent Bit engine) means
     * that is not possible to work on this now and it need to 'retry'.
     */
    if (ctx->blocked == FLB_TRUE) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        ret = produce_message(&tms, obj, ctx, config);
        if (ret == FLB_ERROR) {
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        else if (ret == FLB_RETRY) {
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    msgpack_unpacked_destroy(&result);
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
