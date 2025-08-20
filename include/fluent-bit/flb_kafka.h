/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_KAFKA_H
#define FLB_KAFKA_H

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>

#include <rdkafka.h>

#define FLB_KAFKA_BROKERS             "127.0.0.1"
#define FLB_KAFKA_TOPIC               "fluent-bit"

struct flb_kafka {
    rd_kafka_t *rk;
    char *brokers;
};

struct flb_kafka_opaque {
    /* generic purpose opaque pointer */
    void *ptr;

    /* used only by AWS MSK IAM interface*/
    void *msk_iam_ctx;
};

rd_kafka_conf_t *flb_kafka_conf_create(struct flb_kafka *kafka,
                                       struct mk_list *properties,
                                       int with_group_id);
rd_kafka_topic_partition_list_t *flb_kafka_parse_topics(const char *topics_str);

struct flb_kafka_opaque *flb_kafka_opaque_create();
void flb_kafka_opaque_destroy(struct flb_kafka_opaque *opaque);
void flb_kafka_opaque_set(struct flb_kafka_opaque *opaque, void *ptr, void *msk_iam_ctx);

#endif
