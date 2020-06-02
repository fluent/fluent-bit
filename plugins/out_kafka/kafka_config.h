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

#ifndef FLB_OUT_KAFKA_CONFIG_H
#define FLB_OUT_KAFKA_CONFIG_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>

#include "rdkafka.h"

#define FLB_KAFKA_FMT_JSON  0
#define FLB_KAFKA_FMT_MSGP  1
#define FLB_KAFKA_FMT_GELF  2
#define FLB_KAFKA_BROKERS   "127.0.0.1"
#define FLB_KAFKA_TOPIC     "fluent-bit"
#define FLB_KAFKA_TS_KEY    "@timestamp"

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
#define FLB_JSON_DATE_ISO8601_FMT "%Y-%m-%dT%H:%M:%S"

struct flb_kafka_topic {
    int name_len;
    char *name;
    rd_kafka_topic_t *tp;
    struct mk_list _head;
};

struct flb_kafka {
    /* Config Parameters */
    int format;
    char *brokers;

    /* Optional topic key for routing */
    int topic_key_len;
    char *topic_key;

    int timestamp_key_len;
    char *timestamp_key;
    int timestamp_format;

    int message_key_len;
    char *message_key;

    int message_key_field_len;
    char *message_key_field;

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

    /* Internal */
    rd_kafka_t *producer;
    rd_kafka_conf_t *conf;

    /* Plugin instance */
    struct flb_output_instance *ins;
};

struct flb_kafka *flb_kafka_conf_create(struct flb_output_instance *ins,
                                        struct flb_config *config);
int flb_kafka_conf_destroy(struct flb_kafka *ctx);

#endif
