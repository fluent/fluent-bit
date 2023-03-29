/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2013, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "test.h"

static RD_UNUSED void
print_toppar_list(const rd_kafka_topic_partition_list_t *list) {
        int i;

        TEST_SAY("List count: %d\n", list->cnt);

        for (i = 0; i < list->cnt; i++) {
                const rd_kafka_topic_partition_t *a = &list->elems[i];

                TEST_SAY(
                    " #%d/%d: "
                    "%s [%" PRId32 "] @ %" PRId64
                    ": "
                    "(%" PRIusz ") \"%*s\"\n",
                    i, list->cnt, a->topic, a->partition, a->offset,
                    a->metadata_size, (int)a->metadata_size,
                    (const char *)a->metadata);
        }
}


static void compare_toppar_lists(const rd_kafka_topic_partition_list_t *lista,
                                 const rd_kafka_topic_partition_list_t *listb) {
        int i;

        TEST_ASSERT(lista->cnt == listb->cnt,
                    "different list lengths: %d != %d", lista->cnt, listb->cnt);

        for (i = 0; i < lista->cnt; i++) {
                const rd_kafka_topic_partition_t *a = &lista->elems[i];
                const rd_kafka_topic_partition_t *b = &listb->elems[i];

                if (a->offset != b->offset ||
                    a->metadata_size != b->metadata_size ||
                    memcmp(a->metadata, b->metadata, a->metadata_size))
                        TEST_FAIL_LATER(
                            "Lists did not match at element %d/%d:\n"
                            " a: %s [%" PRId32 "] @ %" PRId64
                            ": "
                            "(%" PRIusz
                            ") \"%*s\"\n"
                            " b: %s [%" PRId32 "] @ %" PRId64
                            ": "
                            "(%" PRIusz ") \"%*s\"",
                            i, lista->cnt, a->topic, a->partition, a->offset,
                            a->metadata_size, (int)a->metadata_size,
                            (const char *)a->metadata, b->topic, b->partition,
                            b->offset, b->metadata_size, (int)b->metadata_size,
                            (const char *)b->metadata);
        }

        TEST_LATER_CHECK();
}


static int commit_cb_cnt = 0;

static void offset_commit_cb(rd_kafka_t *rk,
                             rd_kafka_resp_err_t err,
                             rd_kafka_topic_partition_list_t *list,
                             void *opaque) {
        commit_cb_cnt++;
        TEST_ASSERT(!err, "offset_commit_cb failure: %s",
                    rd_kafka_err2str(err));
}


static void
commit_metadata(const char *group_id,
                const rd_kafka_topic_partition_list_t *toppar_to_commit) {
        rd_kafka_resp_err_t err;
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;

        test_conf_init(&conf, NULL, 20 /*timeout*/);

        test_conf_set(conf, "group.id", group_id);

        rd_kafka_conf_set_offset_commit_cb(conf, offset_commit_cb);

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        TEST_SAY("Committing:\n");
        print_toppar_list(toppar_to_commit);

        err = rd_kafka_commit(rk, toppar_to_commit, 0);
        TEST_ASSERT(!err, "rd_kafka_commit failed: %s", rd_kafka_err2str(err));

        while (commit_cb_cnt == 0)
                rd_kafka_poll(rk, 1000);

        rd_kafka_destroy(rk);
}


static void
get_committed_metadata(const char *group_id,
                       const rd_kafka_topic_partition_list_t *toppar_to_check,
                       const rd_kafka_topic_partition_list_t *expected_toppar) {
        rd_kafka_resp_err_t err;
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_partition_list_t *committed_toppar;

        test_conf_init(&conf, NULL, 20 /*timeout*/);

        test_conf_set(conf, "group.id", group_id);

        committed_toppar = rd_kafka_topic_partition_list_copy(toppar_to_check);

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        err = rd_kafka_committed(rk, committed_toppar, tmout_multip(5000));
        TEST_ASSERT(!err, "rd_kafka_committed failed: %s",
                    rd_kafka_err2str(err));

        compare_toppar_lists(committed_toppar, expected_toppar);

        rd_kafka_topic_partition_list_destroy(committed_toppar);

        rd_kafka_destroy(rk);
}

int main_0099_commit_metadata(int argc, char **argv) {
        rd_kafka_topic_partition_list_t *origin_toppar;
        rd_kafka_topic_partition_list_t *expected_toppar;
        const char *topic = test_mk_topic_name("0099-commit_metadata", 0);
        char group_id[16];

        test_conf_init(NULL, NULL, 20 /*timeout*/);

        test_str_id_generate(group_id, sizeof(group_id));

        test_create_topic(NULL, topic, 1, 1);

        origin_toppar = rd_kafka_topic_partition_list_new(1);

        rd_kafka_topic_partition_list_add(origin_toppar, topic, 0);

        expected_toppar = rd_kafka_topic_partition_list_copy(origin_toppar);

        expected_toppar->elems[0].offset   = 42;
        expected_toppar->elems[0].metadata = rd_strdup("Hello world!");
        expected_toppar->elems[0].metadata_size =
            strlen(expected_toppar->elems[0].metadata);

        get_committed_metadata(group_id, origin_toppar, origin_toppar);

        commit_metadata(group_id, expected_toppar);

        get_committed_metadata(group_id, origin_toppar, expected_toppar);

        rd_kafka_topic_partition_list_destroy(origin_toppar);
        rd_kafka_topic_partition_list_destroy(expected_toppar);

        return 0;
}
