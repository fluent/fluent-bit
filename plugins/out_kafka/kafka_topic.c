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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>

#include "kafka_config.h"
#include "rdkafka.h"

struct flb_kafka_topic *flb_kafka_topic_create(char *name,
                                               struct flb_out_kafka *ctx)
{
    rd_kafka_topic_t *tp;
    struct flb_kafka_topic *topic;

    tp = rd_kafka_topic_new(ctx->kafka.rk, name, NULL);
    if (!tp) {
        flb_plg_error(ctx->ins, "failed to create topic: %s",
                      rd_kafka_err2str(rd_kafka_last_error()));
        return NULL;
    }

    topic = flb_malloc(sizeof(struct flb_kafka_topic));
    if (!topic) {
        flb_errno();
        return NULL;
    }

    topic->name = flb_strdup(name);
    topic->name_len = strlen(name);
    topic->tp = tp;
    mk_list_add(&topic->_head, &ctx->topics);

    return topic;
}

int flb_kafka_topic_destroy(struct flb_kafka_topic *topic,
                            struct flb_out_kafka *ctx)
{
    mk_list_del(&topic->_head);
    rd_kafka_topic_destroy(topic->tp);
    flb_free(topic->name);
    flb_free(topic);

    return 0;
}

int flb_kafka_topic_destroy_all(struct flb_out_kafka *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_kafka_topic *topic;

    mk_list_foreach_safe(head, tmp, &ctx->topics) {
        topic = mk_list_entry(head, struct flb_kafka_topic, _head);
        flb_kafka_topic_destroy(topic, ctx);
        c++;
    }

    return c;
}

/* Get first topic of the list (default topic) */
struct flb_kafka_topic *flb_kafka_topic_default(struct flb_out_kafka *ctx)
{
    struct flb_kafka_topic *topic;

    if (mk_list_is_empty(&ctx->topics) == 0) {
        return NULL;
    }

    topic = mk_list_entry_first(&ctx->topics, struct flb_kafka_topic,
                                _head);
    return topic;
}

struct flb_kafka_topic *flb_kafka_topic_lookup(char *name,
                                               int name_len,
                                               struct flb_out_kafka *ctx)
{
    struct mk_list *head;
    struct flb_kafka_topic *topic;

    if (!ctx->topic_key) {
        return flb_kafka_topic_default(ctx);
    }

    mk_list_foreach(head, &ctx->topics) {
        topic = mk_list_entry(head, struct flb_kafka_topic, _head);
        if (topic->name_len != name_len) {
            continue;
        }

        if (strncmp(name, topic->name, topic->name_len) == 0) {
            return topic;
        }
    }

    /* No matches, return the default topic */
    return flb_kafka_topic_default(ctx);

}
