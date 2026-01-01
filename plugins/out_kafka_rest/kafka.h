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

#ifndef FLB_OUT_KAFKA_REST_H
#define FLB_OUT_KAFKA_REST_H

#define FLB_KAFKA_TIME_KEY   "@timestamp"
#define FLB_KAFKA_TIME_KEYF  "%Y-%m-%dT%H:%M:%S"
#define FLB_KAFKA_TAG_KEY    "_flb-key"

struct flb_kafka_rest {
    /* Kafka specifics */
    long partition;
    char *topic;
    int message_key_len;
    char *message_key;

    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* time key */
    int time_key_len;
    char *time_key;

    /* time key format */
    int time_key_format_len;
    char *time_key_format;

    /* include_tag_key */
    int include_tag_key;
    int tag_key_len;
    char *tag_key;

    /* HTTP URI */
    char uri[256];
    char *url_path;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Plugin instance */
    struct flb_output_instance *ins;

    /* Avro http header*/
    int avro_http_header;
};


#endif
