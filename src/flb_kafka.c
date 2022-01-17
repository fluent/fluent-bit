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

#include "fluent-bit/flb_config.h"
#include "fluent-bit/flb_mem.h"
#include "fluent-bit/flb_str.h"
#include <fluent-bit/flb_kafka.h>
#include <fluent-bit/flb_kv.h>

#include <rdkafka.h>

rd_kafka_conf_t *flb_kafka_conf_create(struct flb_kafka *kafka,
                                       struct mk_list *properties,
                                       int with_group_id)
{
    struct mk_list *head;
    struct flb_kv *kv;
    const char *conf;
    rd_kafka_conf_t *kafka_cfg;
    char errstr[512];

    kafka_cfg = rd_kafka_conf_new();
    if (!kafka_cfg) {
        flb_error("[flb_kafka] Could not initialize kafka config object");
        goto err;
    }

    conf = flb_config_prop_get("client_id", properties);
    if (!conf) {
        conf = "fluent-bit";
    }
    if (rd_kafka_conf_set(kafka_cfg, "client.id", conf,
                errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        flb_error("[flb_kafka] cannot configure client id: %s", errstr);
    }

    if (with_group_id) {
        conf = flb_config_prop_get("group_id", properties);
        if (!conf) {
            conf = "fluent-bit";
        }
        if (rd_kafka_conf_set(kafka_cfg, "group.id", conf,
                    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
            flb_error("[flb_kafka] cannot configure group id: %s", errstr);
        }
    }

    conf = flb_config_prop_get("brokers", properties);
    if (conf) {
        if (rd_kafka_conf_set(kafka_cfg, "bootstrap.servers", conf,
                errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
            flb_error("[flb_kafka] failed to configure brokers: %s", errstr);
            goto err;
        }
        kafka->brokers = flb_strdup(conf);
    }
    else {
        flb_error("config: no brokers defined");
        goto err;
    }

    /* Iterate custom rdkafka properties */
    mk_list_foreach(head, properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strncasecmp(kv->key, "rdkafka.", 8) == 0 &&
            flb_sds_len(kv->key) > 8) {
            if (rd_kafka_conf_set(kafka_cfg, kv->key + 8, kv->val,
                        errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                flb_error("[flb_kafka] cannot configure '%s' property", kv->key + 8);
            }
        }
    }

    return kafka_cfg;

err:
    if (kafka_cfg) {
        flb_free(kafka_cfg);
    }
    return NULL;
}
