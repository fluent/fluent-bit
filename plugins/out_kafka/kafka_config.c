/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_utils.h>

#include "kafka_config.h"
#include "kafka_topic.h"
#include "kafka_callbacks.h"

struct flb_kafka *flb_kafka_conf_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    char *tmp;
    char errstr[512];
    struct mk_list *head;
    struct mk_list *topics;
    struct flb_split_entry *entry;
    struct flb_kafka *ctx;
    struct flb_config_prop *prop;

    /* Configuration context */
    ctx = flb_calloc(1, sizeof(struct flb_kafka));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->blocked = FLB_FALSE;

    /* rdkafka config context */
    ctx->conf = rd_kafka_conf_new();
    if (!ctx->conf) {
        flb_error("[out_kafka] error creating context");
        flb_free(ctx);
        return NULL;
    }

    /* rdkafka configuration parameters */
    ret = rd_kafka_conf_set(ctx->conf, "client.id", "fluent-bit",
                            errstr, sizeof(errstr));
    if (ret != RD_KAFKA_CONF_OK) {
        flb_error("[out_kafka] cannot configure client.id");
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

    /* Iterate custom rdkafka properties */
    mk_list_foreach(head, &ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);
        if (strncasecmp(prop->key, "rdkafka.", 8) == 0 &&
            strlen(prop->key) > 8) {

            ret = rd_kafka_conf_set(ctx->conf, prop->key + 8, prop->val,
                                    errstr, sizeof(errstr));
            if (ret != RD_KAFKA_CONF_OK) {
                flb_error("[out_kafka] cannot configure '%s' property",
                          prop->key + 8);
            }
        }
    }

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
        ctx->timestamp_key = NULL;
        ctx->timestamp_key_len = 0;
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
        flb_error("[out_kafka] failed to create producer: %s",
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
            flb_warn("[out_kafka] invalid topics defined, setting default");
            flb_kafka_topic_create(FLB_KAFKA_TOPIC, ctx);
        }
        else {
            /* Register each topic */
            mk_list_foreach(head, topics) {
                entry = mk_list_entry(head, struct flb_split_entry, _head);
                if (!flb_kafka_topic_create(entry->value, ctx)) {
                    flb_error("[out_kafka] cannot register topic '%s'",
                              entry->value);
                }
            }
            flb_utils_split_free(topics);
        }
    }

    flb_info("[out_kafka] brokers='%s' topics='%s'", ctx->brokers, tmp);
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

    flb_sds_destroy(ctx->gelf_fields.timestamp_key);
    flb_sds_destroy(ctx->gelf_fields.host_key);
    flb_sds_destroy(ctx->gelf_fields.short_message_key);
    flb_sds_destroy(ctx->gelf_fields.full_message_key);
    flb_sds_destroy(ctx->gelf_fields.level_key);

    flb_free(ctx);
    return 0;
}
