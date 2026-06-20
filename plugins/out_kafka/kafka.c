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

#include <inttypes.h>

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_opentelemetry.h>
#include <fluent-bit/aws/flb_aws_msk_iam.h>
#include <fluent-bit/flb_kafka.h>

#include <cmetrics/cmt_encode_opentelemetry.h>
#include <cfl/cfl_hash.h>
#include <ctraces/ctr_decode_msgpack.h>
#include <ctraces/ctr_encode_opentelemetry.h>

#include "kafka_config.h"
#include "kafka_topic.h"

#define FLB_OTEL_LOGS_SCHEMA_KEY "schema"
#define FLB_OTEL_LOGS_SCHEMA_OTLP "otlp"
#define FLB_KAFKA_PARTIAL_QUEUE_FULL_RETRIES 10

struct otlp_logs_resource_partition {
    int64_t resource_id;
    uint64_t resource_hash;
    int has_key;
    char key[17];
    msgpack_sbuffer buffer;
};

static const char *default_logs_body_keys[] = {"log", "message"};

static void init_otlp_logs_options(struct flb_opentelemetry_otlp_logs_options *options)
{
    memset(options, 0, sizeof(*options));
    options->logs_require_otel_metadata = FLB_FALSE;
    options->logs_body_keys = default_logs_body_keys;
    options->logs_body_key_count = sizeof(default_logs_body_keys) /
                                   sizeof(default_logs_body_keys[0]);
    options->logs_body_key_attributes = FLB_FALSE;
}

void cb_kafka_msg(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage,
                  void *opaque)
{
    struct flb_kafka_opaque *op = (struct flb_kafka_opaque *) opaque;
    struct flb_out_kafka *ctx = op ? (struct flb_out_kafka *) op->ptr : NULL;

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
    struct flb_kafka_opaque *op;
    struct flb_out_kafka *ctx;

    op = (struct flb_kafka_opaque *) rd_kafka_opaque(rk);
    ctx = op ? (struct flb_out_kafka *) op->ptr : NULL;

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
    struct flb_out_kafka *ctx;

    /* Configuration */
    ctx = flb_out_kafka_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "failed to initialize");
        return -1;
    }

    /* Set global context */
    flb_output_set_context(ins, ctx);
    return 0;
}

int produce_message(struct flb_time *tm, msgpack_object *map,
                    struct flb_out_kafka *ctx, struct flb_config *config)
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
    flb_sds_t raw_key = NULL;
    struct flb_kafka_topic *topic = NULL;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_object key;
    msgpack_object val;
    flb_sds_t s = NULL;

#ifdef FLB_HAVE_AVRO_ENCODER
    // used to flag when a buffer needs to be freed for avro
    bool avro_fast_buffer = true;

    // avro encoding uses a buffer
    // the majority of lines are fairly small
    // so using static buffer for these is much more efficient
    // larger sizes will allocate
#ifndef AVRO_DEFAULT_BUFFER_SIZE
#define AVRO_DEFAULT_BUFFER_SIZE 2048
#endif
    static char avro_buff[AVRO_DEFAULT_BUFFER_SIZE];

    // don't take lines that are too large
    // these lines will log a warning
    // this roughly a log line of 250000 chars
#ifndef AVRO_LINE_MAX_LEN
#define AVRO_LINE_MAX_LEN 1000000

    // this is a convenience
#define AVRO_FREE(X, Y) if (!X) { flb_free(Y); }
#endif

    // this is just to keep the code cleaner
    // the avro encoding includes
    // an embedded schemaid which is used
    // the embedding is a null byte
    // followed by a 16 byte schemaid
#define AVRO_SCHEMA_OVERHEAD 4 + 1
#endif

    flb_debug("in produce_message\n");
    if (flb_log_check(FLB_LOG_DEBUG))
        msgpack_object_print(stderr, *map);

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
            case FLB_JSON_DATE_ISO8601_NS:
                {
                size_t date_len;
                int len;
                struct tm _tm;
                char time_formatted[36];

                /* Format the time; use microsecond precision (not nanoseconds). */
                gmtime_r(&tm->tm.tv_sec, &_tm);
                date_len = strftime(time_formatted, sizeof(time_formatted) - 1,
                             FLB_JSON_DATE_ISO8601_FMT, &_tm);

                if (ctx->timestamp_format == FLB_JSON_DATE_ISO8601) {
                    len = snprintf(time_formatted + date_len, sizeof(time_formatted) - 1 - date_len,
                                   ".%06" PRIu64 "Z", (uint64_t) tm->tm.tv_nsec / 1000);
                }
                else {
                    /* FLB_JSON_DATE_ISO8601_NS */
                    len = snprintf(time_formatted + date_len, sizeof(time_formatted) - 1 - date_len,
                                   ".%09" PRIu64 "Z", (uint64_t) tm->tm.tv_nsec);
                }
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

        /* Lookup raw_log_key */
        if (ctx->raw_log_key && ctx->format == FLB_KAFKA_FMT_RAW && !raw_key && val.type == MSGPACK_OBJECT_STR) {
            if (key.via.str.size == ctx->raw_log_key_len &&
                    strncmp(key.via.str.ptr, ctx->raw_log_key, ctx->raw_log_key_len) == 0) {
                raw_key = flb_sds_create_len(val.via.str.ptr, val.via.str.size);
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
                        if (memchr(val.via.str.ptr, ',', val.via.str.size)) {
                            /* Don't allow commas in kafkatopic name */
                            flb_warn("',' not allowed in dynamic_kafka topic names");
                            continue;
                        }
                        if (val.via.str.size > 249) {
                            /* Don't allow length of dynamic kafka topics > 249 */
                            flb_warn(" dynamic kafka topic length > 249 not allowed");
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
                        flb_utils_split_free(topics);
                        flb_free(dynamic_topic);
                    }
                }
            }
        }
    }

    if (ctx->format == FLB_KAFKA_FMT_JSON) {
        s = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                        config->json_escape_unicode);
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
#ifdef FLB_HAVE_AVRO_ENCODER
    else if (ctx->format == FLB_KAFKA_FMT_AVRO) {

        flb_plg_debug(ctx->ins, "avro schema ID:%d:\n", ctx->avro_fields.schema_id);
        flb_plg_debug(ctx->ins, "avro schema string:%s:\n", ctx->avro_fields.schema_str);

	// if there's no data then log it and return
        if (mp_sbuf.size == 0) {
            flb_plg_error(ctx->ins, "got zero bytes decoding to avro AVRO:schemaID:%d:\n", ctx->avro_fields.schema_id);
            msgpack_sbuffer_destroy(&mp_sbuf);
            return FLB_OK;
        }

	// is the line is too long log it and return
        if (mp_sbuf.size > AVRO_LINE_MAX_LEN) {
            flb_plg_warn(ctx->ins, "skipping long line AVRO:len:%zu:limit:%zu:schemaID:%d:\n", (size_t)mp_sbuf.size, (size_t)AVRO_LINE_MAX_LEN, ctx->avro_fields.schema_id);
            msgpack_sbuffer_destroy(&mp_sbuf);
            return FLB_OK;
        }

        flb_plg_debug(ctx->ins, "using default buffer AVRO:len:%zu:limit:%zu:schemaID:%d:\n", (size_t)mp_sbuf.size, (size_t)AVRO_DEFAULT_BUFFER_SIZE, ctx->avro_fields.schema_id);
        out_buf = avro_buff;
        out_size = AVRO_DEFAULT_BUFFER_SIZE;

	if (mp_sbuf.size + AVRO_SCHEMA_OVERHEAD >= AVRO_DEFAULT_BUFFER_SIZE) {
            flb_plg_info(ctx->ins, "upsizing to dynamic buffer AVRO:len:%zu:schemaID:%d:\n", (size_t)mp_sbuf.size, ctx->avro_fields.schema_id);
            avro_fast_buffer = false;
            // avro will always be  smaller than msgpack
            // it contains no meta-info aside from the schemaid
            // all the metadata is in the schema which is not part of the msg
            // add schemaid + magic byte for safety buffer and allocate
            // that's 16 byte schemaid and one byte magic byte
            out_size = mp_sbuf.size + AVRO_SCHEMA_OVERHEAD;
            out_buf = flb_malloc(out_size);
            if (!out_buf) {
                flb_plg_error(ctx->ins, "error allocating memory for decoding to AVRO:schema:%s:schemaID:%d:\n", ctx->avro_fields.schema_str, ctx->avro_fields.schema_id);
                msgpack_sbuffer_destroy(&mp_sbuf);
                return FLB_ERROR;
            }
	}

        if(!flb_msgpack_raw_to_avro_sds(mp_sbuf.data, mp_sbuf.size, &ctx->avro_fields, out_buf, &out_size)) {
            flb_plg_error(ctx->ins, "error encoding to AVRO:schema:%s:schemaID:%d:\n", ctx->avro_fields.schema_str, ctx->avro_fields.schema_id);
            msgpack_sbuffer_destroy(&mp_sbuf);
            if (!avro_fast_buffer) {
                flb_free(out_buf);
	    }
            return FLB_ERROR;
        }

    }
#endif
    else if (ctx->format == FLB_KAFKA_FMT_RAW) {
        if (raw_key == NULL) {
            flb_plg_error(ctx->ins, "missing raw_log_key");
            msgpack_sbuffer_destroy(&mp_sbuf);
            return FLB_ERROR;
        }
        out_buf = raw_key;
        out_size = flb_sds_len(raw_key);
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
#ifdef FLB_HAVE_AVRO_ENCODER
        if (ctx->format == FLB_KAFKA_FMT_AVRO) {
            AVRO_FREE(avro_fast_buffer, out_buf)
        }
#endif
        flb_sds_destroy(raw_key);
        return FLB_ERROR;
    }

 retry:
    /*
     * If the local rdkafka queue is full, we retry up to 'queue_full_retries'
     * times set by the configuration (default: 10). If the configuration
     * property was set to '0' or 'false', we don't impose a limit. Use that
     * value under your own risk.
     */
    if (ctx->queue_full_retries > 0 &&
        queue_full_retries >= ctx->queue_full_retries) {
        if (ctx->format != FLB_KAFKA_FMT_MSGP) {
            flb_sds_destroy(s);
        }
        msgpack_sbuffer_destroy(&mp_sbuf);
#ifdef FLB_HAVE_AVRO_ENCODER
        if (ctx->format == FLB_KAFKA_FMT_AVRO) {
            AVRO_FREE(avro_fast_buffer, out_buf)
        }
#endif
        flb_sds_destroy(raw_key);
        /*
         * Unblock the flush requests so that the
         * engine could try sending data again.
         */
        ctx->blocked = FLB_FALSE;
        return FLB_RETRY;
    }

    ret = rd_kafka_produce(topic->tp,
                           RD_KAFKA_PARTITION_UA,
                           RD_KAFKA_MSG_F_COPY,
                           out_buf, out_size,
                           message_key, message_key_len,
                           ctx);

    if (ret == -1) {
        flb_error(
                "%% Failed to produce to topic %s: %s\n",
                rd_kafka_topic_name(topic->tp),
                rd_kafka_err2str(rd_kafka_last_error()));

        /*
         * rdkafka queue is full, keep trying 'locally' for a few seconds,
         * otherwise let the caller to issue a main retry againt the engine.
         */
        if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
            flb_plg_warn(ctx->ins,
                         "internal queue is full, retrying in one second");

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
            flb_time_sleep(1000);
            rd_kafka_poll(ctx->kafka.rk, 0);

            /* Issue a re-try */
            queue_full_retries++;
            goto retry;
        }

        ctx->blocked = FLB_FALSE;
        if (ctx->format == FLB_KAFKA_FMT_JSON ||
            ctx->format == FLB_KAFKA_FMT_GELF) {
            flb_sds_destroy(s);
        }
        msgpack_sbuffer_destroy(&mp_sbuf);
#ifdef FLB_HAVE_AVRO_ENCODER
        if (ctx->format == FLB_KAFKA_FMT_AVRO) {
            AVRO_FREE(avro_fast_buffer, out_buf)
        }
#endif
        flb_sds_destroy(raw_key);
        return FLB_ERROR;
    }
    else {
        flb_plg_debug(ctx->ins, "enqueued message (%zd bytes) for topic '%s'",
                      out_size, rd_kafka_topic_name(topic->tp));
    }
    ctx->blocked = FLB_FALSE;

    rd_kafka_poll(ctx->kafka.rk, 0);
    if (ctx->format == FLB_KAFKA_FMT_JSON) {
        flb_sds_destroy(s);
    }
    if (ctx->format == FLB_KAFKA_FMT_GELF) {
        flb_sds_destroy(s);
    }
#ifdef FLB_HAVE_AVRO_ENCODER
    if (ctx->format == FLB_KAFKA_FMT_AVRO) {
        AVRO_FREE(avro_fast_buffer, out_buf)
    }
#endif
    flb_sds_destroy(raw_key);

    msgpack_sbuffer_destroy(&mp_sbuf);
    return FLB_OK;
}

static int produce_raw_payload_with_key_retry_control(const void *payload,
                                                      size_t payload_size,
                                                      char *key,
                                                      size_t key_len,
                                                      int use_default_key,
                                                      int allow_engine_retry,
                                                      struct flb_out_kafka *ctx)
{
    int ret;
    int queue_full_retries;
    int queue_full_retry_limit;
    char *message_key;
    size_t message_key_len;
    struct flb_kafka_topic *topic;

    if (payload == NULL || payload_size == 0) {
        return FLB_OK;
    }

    queue_full_retries = 0;
    queue_full_retry_limit = ctx->queue_full_retries;
    if (key != NULL) {
        message_key = key;
        message_key_len = key_len;
    }
    else if (use_default_key == FLB_TRUE) {
        message_key = ctx->message_key;
        message_key_len = ctx->message_key_len;
    }
    else {
        message_key = NULL;
        message_key_len = 0;
    }

    if (queue_full_retry_limit <= 0 && allow_engine_retry == FLB_FALSE) {
        queue_full_retry_limit = FLB_KAFKA_PARTIAL_QUEUE_FULL_RETRIES;
    }

    topic = flb_kafka_topic_default(ctx);

    if (topic == NULL) {
        flb_plg_error(ctx->ins, "no default topic found");
        return FLB_ERROR;
    }

retry:
    if (queue_full_retry_limit > 0 &&
        queue_full_retries >= queue_full_retry_limit) {
        ctx->blocked = FLB_FALSE;
        if (allow_engine_retry == FLB_TRUE) {
            return FLB_RETRY;
        }

        flb_plg_error(ctx->ins,
                      "failed to produce partitioned OTLP payload to topic %s: "
                      "internal queue is full after %d retries",
                      rd_kafka_topic_name(topic->tp),
                      queue_full_retries);
        return FLB_ERROR;
    }

    ret = rd_kafka_produce(topic->tp,
                           RD_KAFKA_PARTITION_UA,
                           RD_KAFKA_MSG_F_COPY,
                           (void *) payload,
                           payload_size,
                           message_key,
                           message_key_len,
                           ctx);
    if (ret == -1) {
        if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
            ctx->blocked = FLB_TRUE;
            flb_time_sleep(1000);
            rd_kafka_poll(ctx->kafka.rk, 0);
            queue_full_retries++;
            goto retry;
        }

        ctx->blocked = FLB_FALSE;
        flb_plg_error(ctx->ins,
                      "failed to produce OTLP payload to topic %s: %s",
                      rd_kafka_topic_name(topic->tp),
                      rd_kafka_err2str(rd_kafka_last_error()));
        return FLB_ERROR;
    }

    ctx->blocked = FLB_FALSE;
    rd_kafka_poll(ctx->kafka.rk, 0);

    return FLB_OK;
}

static int produce_raw_payload_with_key(const void *payload, size_t payload_size,
                                        char *key, size_t key_len,
                                        struct flb_out_kafka *ctx)
{
    return produce_raw_payload_with_key_retry_control(payload,
                                                      payload_size,
                                                      key,
                                                      key_len,
                                                      FLB_TRUE,
                                                      FLB_TRUE,
                                                      ctx);
}

static int produce_raw_payload(const void *payload, size_t payload_size,
                               struct flb_out_kafka *ctx)
{
    return produce_raw_payload_with_key(payload, payload_size, NULL, 0, ctx);
}

static msgpack_object *msgpack_map_get_object(msgpack_object_map *map,
                                              const char *key)
{
    size_t index;
    size_t key_length;
    msgpack_object_kv *entry;

    if (map == NULL || key == NULL) {
        return NULL;
    }

    key_length = strlen(key);

    for (index = 0; index < map->size; index++) {
        entry = &map->ptr[index];

        if (entry->key.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (entry->key.via.str.size != key_length) {
            continue;
        }

        if (strncmp(entry->key.via.str.ptr, key, key_length) == 0) {
            return &entry->val;
        }
    }

    return NULL;
}

static int msgpack_map_entry_is_string(msgpack_object_map *map,
                                       const char *key,
                                       const char *expected)
{
    msgpack_object *value;

    value = msgpack_map_get_object(map, key);
    if (value == NULL || value->type != MSGPACK_OBJECT_STR) {
        return FLB_FALSE;
    }

    if (value->via.str.size != strlen(expected)) {
        return FLB_FALSE;
    }

    if (strncmp(value->via.str.ptr, expected, value->via.str.size) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int msgpack_map_get_int64(msgpack_object_map *map,
                                 const char *key,
                                 int64_t *output)
{
    msgpack_object *value;

    value = msgpack_map_get_object(map, key);
    if (value == NULL) {
        return -1;
    }

    if (value->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        *output = (int64_t) value->via.u64;
        return 0;
    }
    else if (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        *output = value->via.i64;
        return 0;
    }

    return -1;
}

static uint64_t msgpack_object_hash(msgpack_object *object)
{
    uint64_t hash;
    msgpack_sbuffer buffer;
    msgpack_packer packer;

    if (object == NULL) {
        return cfl_hash_64bits("null", 4);
    }

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    if (msgpack_pack_object(&packer, *object) != 0) {
        msgpack_sbuffer_destroy(&buffer);
        return 0;
    }

    hash = cfl_hash_64bits(buffer.data, buffer.size);
    msgpack_sbuffer_destroy(&buffer);

    return hash;
}

static uint64_t msgpack_object_pair_hash(msgpack_object *left,
                                         msgpack_object *right)
{
    uint64_t hash;
    msgpack_sbuffer buffer;
    msgpack_packer packer;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    if (msgpack_pack_array(&packer, 2) != 0) {
        msgpack_sbuffer_destroy(&buffer);
        return 0;
    }

    if (left == NULL) {
        msgpack_pack_nil(&packer);
    }
    else if (msgpack_pack_object(&packer, *left) != 0) {
        msgpack_sbuffer_destroy(&buffer);
        return 0;
    }

    if (right == NULL) {
        msgpack_pack_nil(&packer);
    }
    else if (msgpack_pack_object(&packer, *right) != 0) {
        msgpack_sbuffer_destroy(&buffer);
        return 0;
    }

    hash = cfl_hash_64bits(buffer.data, buffer.size);
    msgpack_sbuffer_destroy(&buffer);

    return hash;
}

static msgpack_object *resource_schema_url_object(msgpack_object *resource_object,
                                                  msgpack_object *resource_body)
{
    msgpack_object *schema_url;

    if (resource_body != NULL && resource_body->type == MSGPACK_OBJECT_MAP) {
        schema_url = msgpack_map_get_object(&resource_body->via.map, "schema_url");
        if (schema_url != NULL) {
            return schema_url;
        }
    }

    if (resource_object != NULL && resource_object->type == MSGPACK_OBJECT_MAP) {
        schema_url = msgpack_map_get_object(&resource_object->via.map, "schema_url");
        if (schema_url != NULL) {
            return schema_url;
        }
    }

    return NULL;
}

static uint64_t resource_identity_hash(msgpack_object *resource_object,
                                       msgpack_object *resource_body)
{
    msgpack_object *schema_url;

    schema_url = resource_schema_url_object(resource_object, resource_body);

    return msgpack_object_pair_hash(resource_object, schema_url);
}

static uint64_t resource_attributes_hash(msgpack_object *resource_object)
{
    msgpack_object *attributes;

    if (resource_object == NULL || resource_object->type != MSGPACK_OBJECT_MAP) {
        return msgpack_object_hash(NULL);
    }

    attributes = msgpack_map_get_object(&resource_object->via.map, "attributes");

    return msgpack_object_hash(attributes);
}

static void destroy_otlp_logs_partitions(
    struct otlp_logs_resource_partition *partitions,
    size_t count)
{
    size_t index;

    if (partitions == NULL) {
        return;
    }

    for (index = 0; index < count; index++) {
        msgpack_sbuffer_destroy(&partitions[index].buffer);
    }

    flb_free(partitions);
}

static struct otlp_logs_resource_partition *find_otlp_logs_partition(
    struct otlp_logs_resource_partition *partitions,
    size_t count,
    int64_t resource_id,
    uint64_t resource_hash,
    int has_key)
{
    size_t index;

    for (index = 0; index < count; index++) {
        if (partitions[index].resource_id == resource_id &&
            partitions[index].resource_hash == resource_hash &&
            partitions[index].has_key == has_key) {
            return &partitions[index];
        }
    }

    return NULL;
}

static struct otlp_logs_resource_partition *get_otlp_logs_partition(
    struct otlp_logs_resource_partition **partitions,
    size_t *count,
    int64_t resource_id,
    uint64_t resource_hash,
    uint64_t key_hash,
    int has_key)
{
    struct otlp_logs_resource_partition *partition;
    struct otlp_logs_resource_partition *tmp;

    partition = find_otlp_logs_partition(*partitions,
                                         *count,
                                         resource_id,
                                         resource_hash,
                                         has_key);
    if (partition != NULL) {
        return partition;
    }

    tmp = flb_realloc(*partitions,
                      sizeof(struct otlp_logs_resource_partition) * (*count + 1));
    if (tmp == NULL) {
        flb_errno();
        return NULL;
    }

    *partitions = tmp;
    partition = &(*partitions)[*count];
    memset(partition, 0, sizeof(struct otlp_logs_resource_partition));

    partition->resource_id = resource_id;
    partition->resource_hash = resource_hash;
    partition->has_key = has_key;
    if (has_key == FLB_TRUE) {
        snprintf(partition->key, sizeof(partition->key), "%016" PRIx64, key_hash);
    }

    msgpack_sbuffer_init(&partition->buffer);
    (*count)++;

    return partition;
}

static int append_partition_record(
    struct otlp_logs_resource_partition *partition,
    struct flb_log_event_decoder *decoder)
{
    if (partition == NULL || decoder->record_base == NULL ||
        decoder->record_length == 0) {
        return 0;
    }

    return msgpack_sbuffer_write(&partition->buffer,
                                 decoder->record_base,
                                 decoder->record_length);
}

static int get_otlp_group_resource(msgpack_object *group_metadata,
                                   msgpack_object *group_body,
                                   int64_t *resource_id,
                                   msgpack_object **resource_object)
{
    int ret;
    int64_t scope_id;

    if (group_metadata == NULL ||
        group_metadata->type != MSGPACK_OBJECT_MAP ||
        msgpack_map_entry_is_string(&group_metadata->via.map,
                                    FLB_OTEL_LOGS_SCHEMA_KEY,
                                    FLB_OTEL_LOGS_SCHEMA_OTLP) != FLB_TRUE ||
        msgpack_map_get_int64(&group_metadata->via.map,
                              "resource_id",
                              resource_id) != 0) {
        return -1;
    }

    if (group_body != NULL && group_body->type == MSGPACK_OBJECT_MAP) {
        *resource_object = msgpack_map_get_object(&group_body->via.map,
                                                  "resource");
    }
    else {
        *resource_object = NULL;
    }

    ret = msgpack_map_get_int64(&group_metadata->via.map, "scope_id", &scope_id);
    if (ret != 0) {
        return -1;
    }
    (void) scope_id;

    return 0;
}

static int produce_partitioned_otlp_logs(struct flb_out_kafka *ctx,
                                         struct flb_event_chunk *event_chunk,
                                         int format)
{
    int ret;
    int result;
    int32_t record_type;
    int64_t resource_id;
    uint64_t resource_hash;
    uint64_t key_hash;
    flb_sds_t payload;
    char *key;
    size_t key_len;
    size_t index;
    size_t partition_count;
    msgpack_object *group_body;
    msgpack_object *group_metadata;
    msgpack_object *resource_object;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;
    struct otlp_logs_resource_partition *partition;
    struct otlp_logs_resource_partition *current_partition;
    struct otlp_logs_resource_partition *partitions;
    struct flb_opentelemetry_otlp_logs_options options;
    size_t produced_count;

    partitions = NULL;
    partition_count = 0;
    current_partition = NULL;
    produced_count = 0;

    ret = flb_log_event_decoder_init(&decoder,
                                     (char *) event_chunk->data,
                                     event_chunk->size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "could not decode OTLP log chunk for partitioning: %d",
                      ret);
        return FLB_ERROR;
    }

    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    while ((ret = flb_log_event_decoder_next(&decoder, &event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&event, &record_type);
        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "could not read OTLP log record type for partitioning");
            ret = FLB_ERROR;
            goto cleanup;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            group_metadata = event.group_metadata != NULL ? event.group_metadata : event.metadata;
            group_body = event.body;
            resource_object = NULL;

            ret = get_otlp_group_resource(group_metadata,
                                          group_body,
                                          &resource_id,
                                          &resource_object);
            if (ret == 0) {
                resource_hash = resource_identity_hash(resource_object, group_body);
                key_hash = resource_attributes_hash(resource_object);
                current_partition = get_otlp_logs_partition(&partitions,
                                                            &partition_count,
                                                            resource_id,
                                                            resource_hash,
                                                            key_hash,
                                                            FLB_TRUE);
            }
            else {
                current_partition = get_otlp_logs_partition(&partitions,
                                                            &partition_count,
                                                            -1,
                                                            0,
                                                            0,
                                                            FLB_FALSE);
            }

            if (current_partition == NULL) {
                ret = FLB_ERROR;
                goto cleanup;
            }

            ret = append_partition_record(current_partition, &decoder);
            if (ret != 0) {
                ret = FLB_ERROR;
                goto cleanup;
            }
            continue;
        }
        else if (record_type == FLB_LOG_EVENT_GROUP_END) {
            if (current_partition != NULL) {
                ret = append_partition_record(current_partition, &decoder);
                if (ret != 0) {
                    ret = FLB_ERROR;
                    goto cleanup;
                }
            }
            current_partition = NULL;
            continue;
        }

        if (current_partition == NULL) {
            current_partition = get_otlp_logs_partition(&partitions,
                                                        &partition_count,
                                                        -1,
                                                        0,
                                                        0,
                                                        FLB_FALSE);
            if (current_partition == NULL) {
                ret = FLB_ERROR;
                goto cleanup;
            }
        }

        ret = append_partition_record(current_partition, &decoder);
        if (ret != 0) {
            ret = FLB_ERROR;
            goto cleanup;
        }
    }

    ret = flb_log_event_decoder_get_last_result(&decoder);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "could not decode OTLP log chunk for partitioning: %d",
                      ret);
        ret = FLB_ERROR;
        goto cleanup;
    }

    init_otlp_logs_options(&options);

    for (index = 0; index < partition_count; index++) {
        partition = &partitions[index];
        payload = NULL;

        if (format == FLB_KAFKA_FMT_OTLP_JSON) {
            payload = flb_opentelemetry_logs_to_otlp_json(partition->buffer.data,
                                                          partition->buffer.size,
                                                          &options,
                                                          &result);
        }
        else {
            payload = flb_opentelemetry_logs_to_otlp_proto(partition->buffer.data,
                                                           partition->buffer.size,
                                                           &options,
                                                           &result);
        }

        if (payload == NULL) {
            flb_plg_error(ctx->ins,
                          "could not convert partitioned OTLP logs: %d",
                          result);
            ret = FLB_ERROR;
            goto cleanup;
        }

        if (partition->has_key == FLB_TRUE) {
            key = partition->key;
            key_len = strlen(partition->key);
        }
        else {
            key = NULL;
            key_len = 0;
        }

        /*
         * Partitioned OTLP log sends are at-most-once after the first partition
         * is accepted by librdkafka. If a later partition fails, return FLB_ERROR
         * instead of FLB_RETRY so engine replay does not duplicate partitions
         * already enqueued. Under sustained back-pressure this can partially
         * deliver the original chunk; disable this option or reduce Kafka
         * back-pressure when chunk-level retry durability is required.
         */
        ret = produce_raw_payload_with_key_retry_control(payload,
                                                         flb_sds_len(payload),
                                                         key,
                                                         key_len,
                                                         FLB_FALSE,
                                                         produced_count == 0,
                                                         ctx);

        if (format == FLB_KAFKA_FMT_OTLP_JSON) {
            flb_sds_destroy(payload);
        }
        else {
            flb_opentelemetry_logs_proto_destroy(payload);
        }

        if (ret != FLB_OK) {
            goto cleanup;
        }
        produced_count++;
    }

    ret = FLB_OK;

cleanup:
    flb_log_event_decoder_destroy(&decoder);
    destroy_otlp_logs_partitions(partitions, partition_count);

    return ret;
}

static int produce_otlp_json(struct flb_out_kafka *ctx,
                             struct flb_event_chunk *event_chunk)
{
    int result;
    flb_sds_t payload;
    struct flb_opentelemetry_otlp_logs_options options;

    payload = NULL;

    if (event_chunk->type == FLB_EVENT_TYPE_LOGS) {
        if (ctx->otlp_logs_partition_by_resource == FLB_TRUE) {
            return produce_partitioned_otlp_logs(ctx,
                                                 event_chunk,
                                                 FLB_KAFKA_FMT_OTLP_JSON);
        }

        init_otlp_logs_options(&options);

        payload = flb_opentelemetry_logs_to_otlp_json(event_chunk->data,
                                                      event_chunk->size,
                                                      &options,
                                                      &result);
    }
#ifdef FLB_HAVE_METRICS
    else if (event_chunk->type == FLB_EVENT_TYPE_METRICS) {
        payload = flb_opentelemetry_metrics_msgpack_to_otlp_json(
            event_chunk->data,
            event_chunk->size,
            &result);
    }
#endif
    else if (event_chunk->type == FLB_EVENT_TYPE_TRACES) {
        payload = flb_opentelemetry_traces_msgpack_to_otlp_json(
            event_chunk->data,
            event_chunk->size,
            &result);
    }
    else {
        return FLB_ERROR;
    }

    if (payload == NULL) {
        flb_plg_error(ctx->ins,
                      "could not convert event chunk to OTLP JSON: %d",
                      result);
        return FLB_ERROR;
    }

    result = produce_raw_payload(payload, flb_sds_len(payload), ctx);
    flb_sds_destroy(payload);

    return result;
}

static int produce_otlp_proto(struct flb_out_kafka *ctx,
                              struct flb_event_chunk *event_chunk)
{
    int ret;
    int result;
    size_t off;
    struct ctrace *ctr;
    flb_sds_t payload;
    struct flb_opentelemetry_otlp_logs_options options;

    if (event_chunk->type == FLB_EVENT_TYPE_LOGS) {
        if (ctx->otlp_logs_partition_by_resource == FLB_TRUE) {
            return produce_partitioned_otlp_logs(ctx,
                                                 event_chunk,
                                                 FLB_KAFKA_FMT_OTLP_PROTO);
        }

        init_otlp_logs_options(&options);

        payload = flb_opentelemetry_logs_to_otlp_proto(event_chunk->data,
                                                       event_chunk->size,
                                                       &options,
                                                       &result);
        if (payload == NULL) {
            flb_plg_error(ctx->ins,
                          "could not convert event chunk to OTLP protobuf: %d",
                          result);
            return FLB_ERROR;
        }

        result = produce_raw_payload(payload, flb_sds_len(payload), ctx);
        flb_opentelemetry_logs_proto_destroy(payload);
        return result;
    }
#ifdef FLB_HAVE_METRICS
    else if (event_chunk->type == FLB_EVENT_TYPE_METRICS) {
        payload = flb_opentelemetry_metrics_msgpack_to_otlp_proto(event_chunk->data,
                                                                  event_chunk->size,
                                                                  &result);
        if (payload == NULL) {
            flb_plg_error(ctx->ins,
                          "could not convert metrics chunk to OTLP protobuf: %d",
                          result);
            return FLB_ERROR;
        }

        result = produce_raw_payload(payload, cfl_sds_len((cfl_sds_t) payload), ctx);
        flb_opentelemetry_metrics_proto_destroy(payload);

        return result;
    }
#endif
    else if (event_chunk->type == FLB_EVENT_TYPE_TRACES) {
        off = 0;

        while ((ret = ctr_decode_msgpack_create(&ctr,
                                                (char *) event_chunk->data,
                                                event_chunk->size,
                                                &off)) == CTR_DECODE_MSGPACK_SUCCESS) {
            payload = flb_opentelemetry_traces_to_otlp_proto(ctr, &result);

            if (payload == NULL) {
                ctr_destroy(ctr);
                flb_plg_error(ctx->ins,
                              "could not convert trace context to OTLP protobuf: %d",
                              result);
                return FLB_ERROR;
            }

            result = produce_raw_payload(payload, flb_sds_len(payload), ctx);
            flb_opentelemetry_traces_proto_destroy(payload);
            ctr_destroy(ctr);
            if (result != FLB_OK) {
                return result;
            }
        }

        if (ret == CTR_MPACK_INSUFFICIENT_DATA && off >= event_chunk->size) {
            return FLB_OK;
        }

        if (ret == CTR_MPACK_ENGINE_ERROR && off >= event_chunk->size) {
            return FLB_OK;
        }

        if (ret != CTR_DECODE_MSGPACK_SUCCESS) {
            flb_plg_error(ctx->ins, "could not decode traces msgpack: %d", ret);
            return FLB_ERROR;
        }
    }

    return FLB_ERROR;
}

static void cb_kafka_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{

    int ret;
    struct flb_out_kafka *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    /*
     * If the context is blocked, means rdkafka queue is full and no more
     * messages can be appended. For our called (Fluent Bit engine) means
     * that is not possible to work on this now and it need to 'retry'.
     */
    if (ctx->blocked == FLB_TRUE) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    if (ctx->format == FLB_KAFKA_FMT_OTLP_JSON) {
        FLB_OUTPUT_RETURN(produce_otlp_json(ctx, event_chunk));
    }

    if (ctx->format == FLB_KAFKA_FMT_OTLP_PROTO) {
        FLB_OUTPUT_RETURN(produce_otlp_proto(ctx, event_chunk));
    }

    if (event_chunk->type != FLB_EVENT_TYPE_LOGS) {
        flb_plg_error(ctx->ins,
                      "format '%s' only supports logs; use 'otlp_json' or 'otlp_proto' for metrics and traces",
                      ctx->format_str != NULL ? ctx->format_str : "json");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    ret = flb_log_event_decoder_init(&log_decoder,
                                     (char *) event_chunk->data,
                                     event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Iterate the original buffer and perform adjustments */
    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = produce_message(&log_event.timestamp,
                              log_event.body,
                              ctx, config);

        if (ret != FLB_OK) {
            flb_log_event_decoder_destroy(&log_decoder);

            FLB_OUTPUT_RETURN(ret);
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static void kafka_flush_force(struct flb_out_kafka *ctx,
                              struct flb_config *config)
{
    int ret;

    if (!ctx) {
        return;
    }

    if (ctx->kafka.rk) {
        ret = rd_kafka_flush(ctx->kafka.rk, config->grace * 1000);
        if (ret != RD_KAFKA_RESP_ERR_NO_ERROR) {
            flb_plg_warn(ctx->ins, "Failed to force flush: %s",
                         rd_kafka_err2str(ret));
        }
    }
}

static int cb_kafka_exit(void *data, struct flb_config *config)
{
    struct flb_out_kafka *ctx = data;

    kafka_flush_force(ctx, config);
    flb_out_kafka_destroy(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
   {
    FLB_CONFIG_MAP_STR, "topic_key", (char *)NULL,
    0, FLB_TRUE, offsetof(struct flb_out_kafka, topic_key),
    "Which record to use as the kafka topic."
   },
   {
    FLB_CONFIG_MAP_BOOL, "dynamic_topic", "false",
    0, FLB_TRUE, offsetof(struct flb_out_kafka, dynamic_topic),
    "Activate dynamic topics."
   },
   {
    FLB_CONFIG_MAP_STR, "format", (char *)NULL,
    0, FLB_TRUE, offsetof(struct flb_out_kafka, format_str),
    "Set the record output format. Supported values include json, msgpack, gelf, raw, otlp_json and otlp_proto."
   },
   {
    FLB_CONFIG_MAP_BOOL, "otlp_logs_partition_by_resource", "false",
    0, FLB_TRUE, offsetof(struct flb_out_kafka, otlp_logs_partition_by_resource),
    "When using format otlp_json or otlp_proto, split OTLP log payloads by "
    "resource and use a hash of the resource attributes as the Kafka message key. "
    "This supersedes message_key and message_key_field for those chunks; logs "
    "without resource information are unkeyed. After partial partition delivery, "
    "later produce failures are not retried by the engine to avoid duplicates; "
    "disable this option or reduce Kafka back-pressure for chunk-level retry "
    "durability."
   },
   {
    FLB_CONFIG_MAP_STR, "message_key", (char *)NULL,
    0, FLB_TRUE, offsetof(struct flb_out_kafka, message_key),
    "Which record key to use as the message data."
   },
   {
    FLB_CONFIG_MAP_STR, "message_key_field", (char *)NULL,
    0, FLB_TRUE, offsetof(struct flb_out_kafka, message_key_field),
    "Which record key field to use as the message data."
   },
   {
    FLB_CONFIG_MAP_STR, "timestamp_key", FLB_KAFKA_TS_KEY,
    0, FLB_TRUE, offsetof(struct flb_out_kafka, timestamp_key),
    "Set the key for the the timestamp."
   },
   {
    FLB_CONFIG_MAP_STR, "timestamp_format", (char *)NULL,
    0, FLB_TRUE, offsetof(struct flb_out_kafka, timestamp_format_str),
    "Set the format the timestamp is in."
   },
   {
    FLB_CONFIG_MAP_INT, "queue_full_retries", FLB_KAFKA_QUEUE_FULL_RETRIES,
    0, FLB_TRUE, offsetof(struct flb_out_kafka, queue_full_retries),
    "Set the number of local retries to enqueue the data."
   },
   {
    FLB_CONFIG_MAP_STR, "gelf_timestamp_key", (char *)NULL,
    0, FLB_FALSE,  0,
    "Set the timestamp key for gelf  output."
   },
   {
    FLB_CONFIG_MAP_STR, "gelf_host_key", (char *)NULL,
    0, FLB_FALSE,  0,
    "Set the host key for gelf  output."
   },
   {
    FLB_CONFIG_MAP_STR, "gelf_short_message_key", (char *)NULL,
    0, FLB_FALSE,  0,
    "Set the short message key for gelf  output."
   },
   {
    FLB_CONFIG_MAP_STR, "gelf_full_message_key", (char *)NULL,
    0, FLB_FALSE,  0,
    "Set the full message key for gelf  output."
   },
   {
    FLB_CONFIG_MAP_STR, "gelf_level_key", (char *)NULL,
    0, FLB_FALSE,  0,
    "Set the level key for gelf  output."
   },
#ifdef FLB_HAVE_AVRO_ENCODER
   {
    FLB_CONFIG_MAP_STR, "schema_str", (char *)NULL,
    0, FLB_FALSE, 0,
    "Set AVRO schema."
   },
   {
    FLB_CONFIG_MAP_INT, "schema_id", (char *)NULL,
    0, FLB_TRUE, offsetof(struct flb_out_kafka, avro_fields) + offsetof(struct flb_avro_fields, schema_id),
    "Set AVRO schema ID."
   },
#endif
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
    //FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_out_kafka, rdkafka_opts),
    0,  FLB_FALSE, 0,
    "Set the kafka group_id."
   },
   {
    FLB_CONFIG_MAP_STR, "raw_log_key", NULL,
    0, FLB_TRUE, offsetof(struct flb_out_kafka, raw_log_key),
    "By default, the whole log record will be sent to Kafka. "
    "If you specify a key name with this option, then only the value of "
    "that key will be sent to Kafka."
   },

#ifdef FLB_HAVE_AWS_MSK_IAM
   {
    FLB_CONFIG_MAP_STR, "aws_msk_iam_cluster_arn", NULL,
    0, FLB_TRUE, offsetof(struct flb_out_kafka, aws_msk_iam_cluster_arn),
    "ARN of the MSK cluster when using AWS IAM authentication"
   },
   {
    FLB_CONFIG_MAP_BOOL, "aws_msk_iam", "false",
    0, FLB_TRUE, offsetof(struct flb_out_kafka, aws_msk_iam),
    "Enable AWS MSK IAM authentication"
   },
#endif

   /* EOF */
   {0}
};

struct flb_output_plugin out_kafka_plugin = {
    .name         = "kafka",
    .description  = "Kafka",
    .cb_init      = cb_kafka_init,
    .cb_flush     = cb_kafka_flush,
    .cb_exit      = cb_kafka_exit,
    .config_map   = config_map,
    .flags        = 0,
    .event_type   = FLB_OUTPUT_LOGS
};
