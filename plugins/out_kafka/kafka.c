/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_output.h>

#include "kafka_config.h"
#include "kafka_topic.h"

void cb_kafka_msg(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage,
                  void *opaque)
{
    struct flb_out_kafka *ctx = (struct flb_out_kafka *) opaque;

    if (rkmessage->err) {
        flb_plg_warn(ctx->ins, "message delivery failed: %s",
                     rd_kafka_err2str(rkmessage->err));
#ifdef FLB_HAVE_METRICS
        cmt_counter_inc(ctx->cmt_kafka_errors, cfl_time_now(), 1, (char *[]){flb_output_name(ctx->ins)});
#endif
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
    struct flb_out_kafka *ctx;

    ctx = (struct flb_out_kafka *) rd_kafka_opaque(rk);

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
#define AVRO_SCHEMA_OVERHEAD 16 + 1
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
#ifdef FLB_HAVE_AVRO_ENCODER
    else if (ctx->format == FLB_KAFKA_FMT_AVRO) {

        flb_plg_debug(ctx->ins, "avro schema ID:%s:\n", ctx->avro_fields.schema_id);
        flb_plg_debug(ctx->ins, "avro schema string:%s:\n", ctx->avro_fields.schema_str);

	// if there's no data then log it and return
        if (mp_sbuf.size == 0) {
            flb_plg_error(ctx->ins, "got zero bytes decoding to avro AVRO:schemaID:%s:\n", ctx->avro_fields.schema_id);
            msgpack_sbuffer_destroy(&mp_sbuf);
            return FLB_OK;
        }

	// is the line is too long log it and return
        if (mp_sbuf.size > AVRO_LINE_MAX_LEN) {
            flb_plg_warn(ctx->ins, "skipping long line AVRO:len:%zu:limit:%zu:schemaID:%s:\n", (size_t)mp_sbuf.size, (size_t)AVRO_LINE_MAX_LEN, ctx->avro_fields.schema_id);
            msgpack_sbuffer_destroy(&mp_sbuf);
            return FLB_OK;
        }

        flb_plg_debug(ctx->ins, "using default buffer AVRO:len:%zu:limit:%zu:schemaID:%s:\n", (size_t)mp_sbuf.size, (size_t)AVRO_DEFAULT_BUFFER_SIZE, ctx->avro_fields.schema_id);
        out_buf = avro_buff;
        out_size = AVRO_DEFAULT_BUFFER_SIZE;

	if (mp_sbuf.size + AVRO_SCHEMA_OVERHEAD >= AVRO_DEFAULT_BUFFER_SIZE) {
            flb_plg_info(ctx->ins, "upsizing to dynamic buffer AVRO:len:%zu:schemaID:%s:\n", (size_t)mp_sbuf.size, ctx->avro_fields.schema_id);
            avro_fast_buffer = false;
            // avro will always be  smaller than msgpack
            // it contains no meta-info aside from the schemaid
            // all the metadata is in the schema which is not part of the msg
            // add schemaid + magic byte for safety buffer and allocate
            // that's 16 byte schemaid and one byte magic byte
            out_size = mp_sbuf.size + AVRO_SCHEMA_OVERHEAD;
            out_buf = flb_malloc(out_size);
            if (!out_buf) {
                flb_plg_error(ctx->ins, "error allocating memory for decoding to AVRO:schema:%s:schemaID:%s:\n", ctx->avro_fields.schema_str, ctx->avro_fields.schema_id);
                msgpack_sbuffer_destroy(&mp_sbuf);
                return FLB_ERROR;
            }
	}

        if(!flb_msgpack_raw_to_avro_sds(mp_sbuf.data, mp_sbuf.size, &ctx->avro_fields, out_buf, &out_size)) {
            flb_plg_error(ctx->ins, "error encoding to AVRO:schema:%s:schemaID:%s:\n", ctx->avro_fields.schema_str, ctx->avro_fields.schema_id);
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
    "Set the record output format."
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
    FLB_CONFIG_MAP_STR, "schema_id", (char *)NULL,
    0, FLB_FALSE, 0,
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
    .flags        = 0
};
