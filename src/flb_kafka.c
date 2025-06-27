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
#include "fluent-bit/flb_utils.h"
#include "monkey/mk_core/mk_list.h"
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
                flb_error("[flb_kafka] cannot configure '%s' property with error: '%s'",
                          kv->key + 8, errstr);
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

static int add_topic_partitions(rd_kafka_topic_partition_list_t *list,
                                const char *topic_str,
                                const char *partitions_str)
{
    int ret = -1;
    struct mk_list *split;
    char *str, *end;
    int start, stop;
    size_t len;
    split = flb_utils_split(partitions_str, '-', -1);
    if (!split) {
        flb_error("[flb_kafka] Failed to split partitions string");
        goto end;
    }

    len = mk_list_size(split);
    if (len == 1) {
        str = mk_list_entry(split->next, struct flb_split_entry, _head)->value;
        start = strtol(str, &end, 10);
        if (end == str || *end != '\0') {
            flb_error("[flb_kafka] invalid partition \"%s\"", str);
            goto end;
        }
        // single partition
        rd_kafka_topic_partition_list_add(list, topic_str, start);
    } else if (len == 2) {
        str = mk_list_entry(split->next, struct flb_split_entry, _head)->value;
        start = strtol(str, &end, 10);
        if (end == str || *end != '\0') {
            flb_error("[flb_kafka] invalid partition \"%s\"", str);
            goto end;
        }
        str = mk_list_entry(split->next->next, struct flb_split_entry, _head)->value;
        stop = strtol(str, &end, 10);
        if (end == str || *end != '\0') {
            flb_error("[flb_kafka] invalid partition \"%s\"", str);
            goto end;
        }
        rd_kafka_topic_partition_list_add_range(list, topic_str, start, stop);
    } else {
        flb_error("[flb_kafka] invalid partition range string \"%s\"", partitions_str);
        goto end;
    }

    ret = 0;

end:
    if (split) {
        flb_utils_split_free(split);
    }
    return ret;
}

rd_kafka_topic_partition_list_t *flb_kafka_parse_topics(const char *topics_str)
{
    rd_kafka_topic_partition_list_t *ret;
    struct mk_list *split = NULL;
    struct mk_list *partitions = NULL;
    struct mk_list *curr;
    struct flb_split_entry *entry;
    struct flb_split_entry *topic_entry;
    struct flb_split_entry *partitions_entry;
    size_t len;

    ret = rd_kafka_topic_partition_list_new(1);
    if (!ret) {
        flb_error("[flb_kafka] Failed to allocate topic list");
        goto err;
    }

    split = flb_utils_split(topics_str, ',', -1);
    if (!split) {
        flb_error("[flb_kafka] Failed to split topics string");
        goto err;
    }

    mk_list_foreach(curr, split) {
        entry = mk_list_entry(curr, struct flb_split_entry, _head);
        partitions = flb_utils_split(entry->value, ':', -1);
        if (!partitions) {
            flb_error("[flb_kafka] Failed to split topic string");
            goto err;
        }
        len = mk_list_size(partitions);
        if (len == 1) {
            rd_kafka_topic_partition_list_add(ret, entry->value, 0);
        } else if (len == 2) {
            topic_entry = mk_list_entry(
                    partitions->next, struct flb_split_entry, _head);
            partitions_entry = mk_list_entry(
                    partitions->next->next, struct flb_split_entry, _head);
            if (add_topic_partitions(ret, topic_entry->value, partitions_entry->value)) {
                goto err;
            }
        } else {
            flb_error("[flb_kafka] Failed to parse topic/partition string");
            goto err;
        }
        flb_utils_split_free(partitions);
    }
    flb_utils_split_free(split);
    return ret;

err:
    if (ret) {
        rd_kafka_topic_partition_list_destroy(ret);
    }
    if (split) {
        flb_utils_split_free(split);
    }
    if (partitions) {
        flb_utils_split_free(partitions);
    }
    return NULL;
}
