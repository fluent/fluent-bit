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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_utils.h>

#include "kafka_config.h"
#include "kafka_topic.h"
#include "kafka_callbacks.h"

struct flb_kafka *flb_kafka_conf_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    const char *tmp;
    char errstr[512];
    struct mk_list *head;
    struct mk_list *topics;
    struct flb_split_entry *entry;
    struct flb_kafka *ctx;
    struct flb_kv *kv;

    /* Configuration context */
    ctx = flb_calloc(1, sizeof(struct flb_kafka));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->blocked = FLB_FALSE;

    /* rdkafka config context */
    ctx->conf = rd_kafka_conf_new();
    if (!ctx->conf) {
        flb_plg_error(ctx->ins, "error creating context");
        flb_free(ctx);
        return NULL;
    }

    /* rdkafka configuration parameters */
    ret = rd_kafka_conf_set(ctx->conf, "client.id", "fluent-bit",
                            errstr, sizeof(errstr));
    if (ret != RD_KAFKA_CONF_OK) {
        flb_plg_error(ctx->ins, "cannot configure client.id");
    }

    /* Config: Brokers */
    tmp = flb_output_get_property("brokers", ins);
    if (tmp) {
        ret = rd_kafka_conf_set(ctx->conf,
                                "bootstrap.servers",
                                tmp,
                                errstr, sizeof(errstr));
        if (ret != RD_KAFKA_CONF_OK) {
            flb_plg_error(ctx->ins, "config: %s", errstr);
            flb_free(ctx);
            return NULL;
        }
        ctx->brokers = flb_strdup(tmp);
    }
    else {
        flb_plg_error(ctx->ins, "config: no brokers defined");
        flb_free(ctx);
        return NULL;
    }

    /* Iterate custom rdkafka properties */
    mk_list_foreach(head, &ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strncasecmp(kv->key, "rdkafka.", 8) == 0 &&
            flb_sds_len(kv->key) > 8) {

            ret = rd_kafka_conf_set(ctx->conf, kv->key + 8, kv->val,
                                    errstr, sizeof(errstr));
            if (ret != RD_KAFKA_CONF_OK) {
                flb_plg_error(ctx->ins, "cannot configure '%s' property",
                              kv->key + 8);
            }
        }
    }

    /* Set our global opaque data (plugin context*/
    rd_kafka_conf_set_opaque(ctx->conf, ctx);

    /* Callback: message delivery */
    rd_kafka_conf_set_dr_msg_cb(ctx->conf, cb_kafka_msg);

    /* Callback: log */
    rd_kafka_conf_set_log_cb(ctx->conf, cb_kafka_logger);

    /* Config: Topic_Key */
    tmp = flb_output_get_property("topic_key", ins);
    if (tmp) {
        ctx->topic_key = flb_strdup(tmp);
        ctx->topic_key_len = strlen(tmp);
    }
    else {
        ctx->topic_key = NULL;
    }

    /* Config: dynamic_topic */
    tmp = flb_output_get_property("dynamic_topic", ins);
    if (tmp) {
        ctx->dynamic_topic = flb_utils_bool(tmp);
    }
    else {
        ctx->dynamic_topic = FLB_FALSE;
    }

    /* Config: Format */
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "json") == 0) {
            ctx->format = FLB_KAFKA_FMT_JSON;
        }
        else if (strcasecmp(tmp, "msgpack") == 0) {
            ctx->format = FLB_KAFKA_FMT_MSGP;
        }
        else if (strcasecmp(tmp, "gelf") == 0) {
            ctx->format = FLB_KAFKA_FMT_GELF;
        }
    }
    else {
        ctx->format = FLB_KAFKA_FMT_JSON;
    }

    /* Config: Message_Key */
    tmp = flb_output_get_property("message_key", ins);
    if (tmp) {
        ctx->message_key = flb_strdup(tmp);
        ctx->message_key_len = strlen(tmp);
    }
    else {
        ctx->message_key = NULL;
        ctx->message_key_len = 0;
    }

    /* Config: Message_Key_Field */
    tmp = flb_output_get_property("message_key_field", ins);
    if (tmp) {
        ctx->message_key_field = flb_strdup(tmp);
        ctx->message_key_field_len = strlen(tmp);
    }
    else {
        ctx->message_key_field = NULL;
        ctx->message_key_field_len = 0;
    }

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

    /* Config: Timestamp_Format */
    ctx->timestamp_format = FLB_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("timestamp_format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "iso8601") == 0) {
            ctx->timestamp_format = FLB_JSON_DATE_ISO8601;
        }
    }

    /* Config Gelf_Timestamp_Key */
    tmp = flb_output_get_property("gelf_timestamp_key", ins);
    if (tmp) {
        ctx->gelf_fields.timestamp_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Host_Key */
    tmp = flb_output_get_property("gelf_host_key", ins);
    if (tmp) {
        ctx->gelf_fields.host_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Short_Message_Key */
    tmp = flb_output_get_property("gelf_short_message_key", ins);
    if (tmp) {
        ctx->gelf_fields.short_message_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Full_Message_Key */
    tmp = flb_output_get_property("gelf_full_message_key", ins);
    if (tmp) {
        ctx->gelf_fields.full_message_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Level_Key */
    tmp = flb_output_get_property("gelf_level_key", ins);
    if (tmp) {
        ctx->gelf_fields.level_key = flb_sds_create(tmp);
    }

    /* Kafka Producer */
    ctx->producer = rd_kafka_new(RD_KAFKA_PRODUCER, ctx->conf,
                                 errstr, sizeof(errstr));
    if (!ctx->producer) {
        flb_plg_error(ctx->ins, "failed to create producer: %s",
                      errstr);
        flb_kafka_conf_destroy(ctx);
        return NULL;
    }

    /* Config: Topic */
    mk_list_init(&ctx->topics);
    tmp = flb_output_get_property("topics", ins);
    if (!tmp) {
        flb_kafka_topic_create(FLB_KAFKA_TOPIC, ctx);
    }
    else {
        topics = flb_utils_split(tmp, ',', -1);
        if (!topics) {
            flb_plg_warn(ctx->ins, "invalid topics defined, setting default");
            flb_kafka_topic_create(FLB_KAFKA_TOPIC, ctx);
        }
        else {
            /* Register each topic */
            mk_list_foreach(head, topics) {
                entry = mk_list_entry(head, struct flb_split_entry, _head);
                if (!flb_kafka_topic_create(entry->value, ctx)) {
                    flb_plg_error(ctx->ins, "cannot register topic '%s'",
                                  entry->value);
                }
            }
            flb_utils_split_free(topics);
        }
    }

    flb_plg_info(ctx->ins, "brokers='%s' topics='%s'", ctx->brokers, tmp);
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

    flb_kafka_topic_destroy_all(ctx);

    if (ctx->producer) {
        rd_kafka_destroy(ctx->producer);
    }

    if (ctx->topic_key) {
        flb_free(ctx->topic_key);
    }

    if (ctx->message_key) {
        flb_free(ctx->message_key);
    }

    if (ctx->message_key_field) {
        flb_free(ctx->message_key_field);
    }

    flb_sds_destroy(ctx->gelf_fields.timestamp_key);
    flb_sds_destroy(ctx->gelf_fields.host_key);
    flb_sds_destroy(ctx->gelf_fields.short_message_key);
    flb_sds_destroy(ctx->gelf_fields.full_message_key);
    flb_sds_destroy(ctx->gelf_fields.level_key);

    flb_free(ctx);
    return 0;
}
