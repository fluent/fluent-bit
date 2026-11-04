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

#ifndef FLB_OUT_MQTT_H
#define FLB_OUT_MQTT_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core.h>

#define FLB_MQTT_DEFAULT_HOST             "127.0.0.1"
#define FLB_MQTT_DEFAULT_PORT             1883
#define FLB_MQTT_DEFAULT_TLS_PORT         8883

/*
 * Defaults of the numeric properties, they must match the config map. They
 * are also set before the config map is applied: a property set to an empty
 * value (an unset environment variable) is skipped by the config map.
 */
#define FLB_MQTT_DEFAULT_QOS              1
#define FLB_MQTT_DEFAULT_KEEP_ALIVE       60
#define FLB_MQTT_DEFAULT_MAX_INFLIGHT     64

/*
 * Broker acknowledgements are read with the connection I/O timeout, if
 * net.io_timeout is not set this value is used so a stalled broker cannot
 * block a flush forever.
 */
#define FLB_MQTT_DEFAULT_IO_TIMEOUT       30

/* PUBLISH packets buffered before they are written to the socket */
#define FLB_MQTT_WRITE_BUFFER_SIZE        (256 * 1024)

/* Receive buffer for broker control packets (CONNACK and PUBACK) */
#define FLB_MQTT_READ_BUFFER_SIZE         1024

/* Stale keepalive connections dropped before opening a new one */
#define FLB_MQTT_MAX_STALE_CONNECTIONS    8

/*
 * Generated client identifiers are 'flb' + 12 random hex digits (instance)
 * + 8 hex digits (connection sequence): 23 characters from [0-9a-zA-Z], the
 * length and alphabet every MQTT 3.1.1 server must accept.
 */
#define FLB_MQTT_CLIENT_ID_PREFIX_LEN     15
#define FLB_MQTT_CLIENT_ID_SIZE           32

/* Payload formats */
#define FLB_MQTT_FORMAT_JSON              0
#define FLB_MQTT_FORMAT_MSGPACK           1

/* Topic template parts */
#define FLB_MQTT_TOPIC_LITERAL            0
#define FLB_MQTT_TOPIC_TAG                1
#define FLB_MQTT_TOPIC_TAG_PART           2

/* Upper limit for $TAG[n] */
#define FLB_MQTT_TOPIC_MAX_TAG_PART       1024

struct flb_out_mqtt_topic_part {
    int type;
    int index;               /* FLB_MQTT_TOPIC_TAG_PART only */
    flb_sds_t literal;       /* FLB_MQTT_TOPIC_LITERAL only */
    struct mk_list _head;
};

struct flb_out_mqtt {
    /* Configuration properties */
    flb_sds_t topic;
    flb_sds_t topic_key;
    int qos;
    int retain;
    flb_sds_t client_id;
    flb_sds_t username;
    flb_sds_t password;
    int keep_alive;
    flb_sds_t payload_key;
    flb_sds_t json_date_key;
    int max_inflight;

    /* Payload format */
    int out_format;
    int json_date_format;
    flb_sds_t date_key;

    /* Topic template, parsed once at init */
    int topic_has_tag;
    struct mk_list topic_parts;

    /* Optional per record topic and payload */
    struct flb_record_accessor *ra_topic_key;
    struct flb_record_accessor *ra_payload_key;

    /* Client identifier */
    int fixed_client_id;
    char client_id_prefix[FLB_MQTT_CLIENT_ID_SIZE];
    unsigned int client_id_seq;

    /* Connection sequence of generated identifiers, workers share it */
    pthread_mutex_t lock;
    int lock_initialized;

    /* Upstream connection to the broker */
    struct flb_upstream *u;

    struct flb_output_instance *ins;
};

#endif
