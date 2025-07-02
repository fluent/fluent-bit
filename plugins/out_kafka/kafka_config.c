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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/aws/flb_aws_msk_iam.h>

#include "kafka_config.h"
#include "kafka_topic.h"
#include "kafka_callbacks.h"


struct flb_out_kafka *flb_out_kafka_create(struct flb_output_instance *ins,
                                           struct flb_config *config)
{
    int ret;
    const char *tmp;
    char errstr[512];
    struct mk_list *head;
    struct mk_list *topics;
    struct flb_split_entry *entry;
    struct flb_out_kafka *ctx;
    rd_kafka_conf_res_t res;

    /* Configuration context */
    ctx = flb_calloc(1, sizeof(struct flb_out_kafka));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->blocked = FLB_FALSE;

    ret = flb_output_config_map_set(ins, (void*) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration.");
        flb_free(ctx);

        return NULL;
    }

#ifdef FLB_HAVE_AWS_MSK_IAM
    /*
     * When MSK IAM auth is enabled, default the required
     * security settings so users don't need to specify them.
     */
    if (ctx->aws_msk_iam && ctx->aws_msk_iam_cluster_arn) {
        tmp = flb_output_get_property("rdkafka.security.protocol", ins);
        if (!tmp) {
            flb_output_set_property(ins, "rdkafka.security.protocol", "SASL_SSL");
        }

        tmp = flb_output_get_property("rdkafka.sasl.mechanism", ins);
        if (!tmp) {
            flb_output_set_property(ins, "rdkafka.sasl.mechanism", "OAUTHBEARER");
            ctx->sasl_mechanism = flb_sds_create("OAUTHBEARER");
        }
        else {
            ctx->sasl_mechanism = flb_sds_create(tmp);
        }
    }
    else {
#endif
        /* Retrieve SASL mechanism if configured */
        tmp = flb_output_get_property("rdkafka.sasl.mechanism", ins);
        if (tmp) {
            ctx->sasl_mechanism = flb_sds_create(tmp);
        }

#ifdef FLB_HAVE_AWS_MSK_IAM
    }
#endif

    /* rdkafka config context */
    ctx->conf = flb_kafka_conf_create(&ctx->kafka, &ins->properties, 0);
    if (!ctx->conf) {
        flb_plg_error(ctx->ins, "error creating context");
        flb_sds_destroy(ctx->sasl_mechanism);
        flb_free(ctx);
        return NULL;
    }


    /* Callback: message delivery */
    rd_kafka_conf_set_dr_msg_cb(ctx->conf, cb_kafka_msg);

    /* Callback: log */
    rd_kafka_conf_set_log_cb(ctx->conf, cb_kafka_logger);

    /* Config: Topic_Key */
    if (ctx->topic_key) {
        ctx->topic_key_len = strlen(ctx->topic_key);
    }

    /* Config: Format */
    if (ctx->format_str) {
        if (strcasecmp(ctx->format_str, "json") == 0) {
            ctx->format = FLB_KAFKA_FMT_JSON;
        }
        else if (strcasecmp(ctx->format_str, "msgpack") == 0) {
            ctx->format = FLB_KAFKA_FMT_MSGP;
        }
        else if (strcasecmp(ctx->format_str, "gelf") == 0) {
            ctx->format = FLB_KAFKA_FMT_GELF;
        }
#ifdef FLB_HAVE_AVRO_ENCODER
        else if (strcasecmp(ctx->format_str, "avro") == 0) {
            ctx->format = FLB_KAFKA_FMT_AVRO;
        }
#endif
        else if (strcasecmp(ctx->format_str, "raw") == 0) {
            ctx->format = FLB_KAFKA_FMT_RAW;
        }
    }
    else {
        ctx->format = FLB_KAFKA_FMT_JSON;
    }

    /* Config: Message_Key */
    if (ctx->message_key) {
        ctx->message_key_len = strlen(ctx->message_key);
    }
    else {
        ctx->message_key_len = 0;
    }

    /* Config: Message_Key_Field */
    if (ctx->message_key_field) {
        ctx->message_key_field_len = strlen(ctx->message_key_field);
    }
    else {
        ctx->message_key_field_len = 0;
    }

    /* Config: Log_Key */
    if (ctx->raw_log_key) {
        ctx->raw_log_key_len = strlen(ctx->raw_log_key);
    }
    else {
        ctx->raw_log_key_len = 0;
    }

    /* Config: Timestamp_Key */
    if (ctx->timestamp_key) {
        ctx->timestamp_key_len = strlen(ctx->timestamp_key);
    }

    /* Config: Timestamp_Format */
    ctx->timestamp_format = FLB_JSON_DATE_DOUBLE;
    if (ctx->timestamp_format_str) {
        if (strcasecmp(ctx->timestamp_format_str, "iso8601") == 0) {
        ctx->timestamp_format = FLB_JSON_DATE_ISO8601;
        }
        else if (strcasecmp(ctx->timestamp_format_str, "iso8601_ns") == 0) {
            ctx->timestamp_format = FLB_JSON_DATE_ISO8601_NS;
        }
    }

    /* set number of retries: note that if the number is zero, means forever */
    if (ctx->queue_full_retries < 0) {
        ctx->queue_full_retries = 0;
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

    /* create and setup opaque context */
    ctx->opaque = flb_kafka_opaque_create();
    if (!ctx->opaque) {
        flb_plg_error(ctx->ins, "failed to create opaque context");
        flb_out_kafka_destroy(ctx);
        return NULL;
    }

    /* store the plugin context so callbacks can log properly */
    flb_kafka_opaque_set(ctx->opaque, ctx, NULL);
    rd_kafka_conf_set_opaque(ctx->conf, ctx->opaque);

#ifdef FLB_HAVE_AWS_MSK_IAM
    if (ctx->aws_msk_iam && ctx->aws_msk_iam_cluster_arn && ctx->sasl_mechanism &&
        strcasecmp(ctx->sasl_mechanism, "OAUTHBEARER") == 0) {

        ctx->msk_iam = flb_aws_msk_iam_register_oauth_cb(config,
                                                         ctx->conf,
                                                         ctx->aws_msk_iam_cluster_arn,
                                                         ctx->opaque);
        if (!ctx->msk_iam) {
            flb_plg_error(ctx->ins, "failed to setup MSK IAM authentication");
        }
        else {
            res = rd_kafka_conf_set(ctx->conf, "sasl.oauthbearer.config",
                                    "principal=admin", errstr, sizeof(errstr));
            if (res != RD_KAFKA_CONF_OK) {
                flb_plg_error(ctx->ins,
                             "failed to set sasl.oauthbearer.config: %s",
                             errstr);
            }
        }
    }
#endif

    /* Kafka Producer */
    ctx->kafka.rk = rd_kafka_new(RD_KAFKA_PRODUCER, ctx->conf,
                                 errstr, sizeof(errstr));
    if (!ctx->kafka.rk) {
        flb_plg_error(ctx->ins, "failed to create producer: %s",
                      errstr);
        flb_out_kafka_destroy(ctx);
        return NULL;
    }

#ifdef FLB_HAVE_AVRO_ENCODER
    /* Config AVRO */
    tmp = flb_output_get_property("schema_str", ins);
    if (tmp) {
        ctx->avro_fields.schema_str = flb_sds_create(tmp);
    }
    tmp = flb_output_get_property("schema_id", ins);
    if (tmp) {
        ctx->avro_fields.schema_id = flb_sds_create(tmp);
    }
#endif

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

    flb_plg_info(ctx->ins, "brokers='%s' topics='%s'", ctx->kafka.brokers, tmp);
#ifdef FLB_HAVE_AVRO_ENCODER
    flb_plg_info(ctx->ins, "schemaID='%s' schema='%s'", ctx->avro_fields.schema_id, ctx->avro_fields.schema_str);
#endif

    return ctx;
}

int flb_out_kafka_destroy(struct flb_out_kafka *ctx)
{
    if (!ctx) {
        return 0;
    }

    if (ctx->kafka.brokers) {
        flb_free(ctx->kafka.brokers);
    }

    flb_kafka_topic_destroy_all(ctx);

    if (ctx->kafka.rk) {
        rd_kafka_destroy(ctx->kafka.rk);
    }

    if (ctx->opaque) {
        flb_kafka_opaque_destroy(ctx->opaque);
    }

    if (ctx->topic_key) {
        flb_free(ctx->topic_key);
    }

    if (ctx->message_key_field) {
        flb_free(ctx->message_key_field);
    }

    flb_sds_destroy(ctx->gelf_fields.timestamp_key);
    flb_sds_destroy(ctx->gelf_fields.host_key);
    flb_sds_destroy(ctx->gelf_fields.short_message_key);
    flb_sds_destroy(ctx->gelf_fields.full_message_key);
    flb_sds_destroy(ctx->gelf_fields.level_key);

#ifdef FLB_HAVE_AWS_MSK_IAM
    if (ctx->msk_iam) {
        flb_aws_msk_iam_destroy(ctx->msk_iam);
    }
#endif

    flb_sds_destroy(ctx->sasl_mechanism);

#ifdef FLB_HAVE_AVRO_ENCODER
    // avro
    flb_sds_destroy(ctx->avro_fields.schema_id);
    flb_sds_destroy(ctx->avro_fields.schema_str);
#endif

    flb_free(ctx);
    return 0;
}
