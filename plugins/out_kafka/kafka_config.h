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

#ifndef FLB_OUT_KAFKA_CONFIG_H
#define FLB_OUT_KAFKA_CONFIG_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#ifdef FLB_HAVE_AVRO_ENCODER
#include <fluent-bit/flb_avro.h>
#endif

#include <fluent-bit/flb_kafka.h>
#include <fluent-bit/aws/flb_aws_msk_iam.h>

#define FLB_KAFKA_FMT_JSON            0
#define FLB_KAFKA_FMT_MSGP            1
#define FLB_KAFKA_FMT_GELF            2
#ifdef FLB_HAVE_AVRO_ENCODER
#define FLB_KAFKA_FMT_AVRO            3
#endif
#define FLB_KAFKA_FMT_RAW             4
#define FLB_KAFKA_TS_KEY              "@timestamp"
#define FLB_KAFKA_QUEUE_FULL_RETRIES  "10"

/* rdkafka log levels based on syslog(3) */
#define FLB_KAFKA_LOG_EMERG   0
#define FLB_KAFKA_LOG_ALERT   1
#define FLB_KAFKA_LOG_CRIT    2
#define FLB_KAFKA_LOG_ERR     3
#define FLB_KAFKA_LOG_WARNING 4
#define FLB_KAFKA_LOG_NOTICE  5
#define FLB_KAFKA_LOG_INFO    6
#define FLB_KAFKA_LOG_DEBUG   7

#define FLB_JSON_DATE_DOUBLE      0
#define FLB_JSON_DATE_ISO8601     1
#define FLB_JSON_DATE_ISO8601_NS  2
#define FLB_JSON_DATE_ISO8601_FMT "%Y-%m-%dT%H:%M:%S"

struct flb_kafka_topic {
    int name_len;
    char *name;
    rd_kafka_topic_t *tp;
    struct mk_list _head;
};

struct flb_out_kafka {
    struct flb_kafka kafka;
    /* Config Parameters */
    int format;
    flb_sds_t format_str;

    /* Optional topic key for routing */
    int topic_key_len;
    char *topic_key;

    int timestamp_key_len;
    char *timestamp_key;
    int timestamp_format;
    flb_sds_t timestamp_format_str;

    int message_key_len;
    char *message_key;

    int message_key_field_len;
    char *message_key_field;

    int raw_log_key_len;
    char *raw_log_key;

    /* Gelf Keys */
    struct flb_gelf_fields gelf_fields;

    /* Head of defined topics by configuration */
    struct mk_list topics;

    /*
     * Blocked Status: since rdkafka have it own buffering queue, there is a
     * chance that the queue becomes full, when that happens our default
     * behavior is the following:
     *
     * - out_kafka yields and try to continue every second until it succeed. In
     *   the meanwhile blocked flag gets FLB_TRUE value.
     * - when flushing more records and blocked == FLB_TRUE, issue
     *   a retry.
     */
    int blocked;

    int dynamic_topic;

    int queue_full_retries;

    /* Internal */
    rd_kafka_conf_t *conf;

    /* Plugin instance */
    struct flb_output_instance *ins;

#ifdef FLB_HAVE_AVRO_ENCODER
    // avro serialization requires a schema
    // the schema is stored in json in avro_schema_str
    //
    // optionally the schema ID can be stashed in the avro data stream
    // the schema ID is stored in avro_schema_id
    // this is common at this time with large kafka installations and schema registries
    // flb_sds_t avro_schema_str;
    // flb_sds_t avro_schema_id;
    struct flb_avro_fields avro_fields;
#endif

#ifdef FLB_HAVE_AWS_MSK_IAM
    struct flb_aws_msk_iam *msk_iam;
    int aws_msk_iam;  /* Flag to indicate user explicitly requested AWS MSK IAM */
    char *aws_region;  /* AWS region for MSK IAM (optional, auto-detected if not set) */
#endif

    struct flb_kafka_opaque *opaque;

    /* SASL mechanism configured in rdkafka.sasl.mechanism */
    flb_sds_t sasl_mechanism;

};

struct flb_out_kafka *flb_out_kafka_create(struct flb_output_instance *ins,
                                           struct flb_config *config);
int flb_out_kafka_destroy(struct flb_out_kafka *ctx);

#endif
