/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2023, Confluent Inc.
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

#include "../src/rdkafka_proto.h"

#include <stdarg.h>

/**
 * @brief Verify that a error codes returned by the OffsetCommit call of
 *        AlterConsumerGroupOffsets return the corresponding error code
 *        in the passed partition.
 */
static void do_test_AlterConsumerGroupOffsets_errors(int req_timeout_ms) {
#define TEST_ERR_SIZE 10
        int i, j;
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        rd_kafka_queue_t *q;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_topic_partition_list_t *to_alter;
        const rd_kafka_topic_partition_list_t *partitions;
        rd_kafka_AlterConsumerGroupOffsets_t *cgoffsets;
        const rd_kafka_AlterConsumerGroupOffsets_result_t *res;
        const rd_kafka_group_result_t **gres;
        size_t gres_cnt;
        char errstr[512];
        const char *bootstraps;
        const char *topic                       = "test";
        const char *group_id                    = topic;
        rd_kafka_AdminOptions_t *options        = NULL;
        rd_kafka_event_t *rkev                  = NULL;
        rd_kafka_resp_err_t errs[TEST_ERR_SIZE] = {
            RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS,
            RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
            RD_KAFKA_RESP_ERR_INVALID_GROUP_ID,
            RD_KAFKA_RESP_ERR_INVALID_COMMIT_OFFSET_SIZE,
            RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED,
            RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,
            RD_KAFKA_RESP_ERR_OFFSET_METADATA_TOO_LARGE,
            RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED};

        SUB_TEST_QUICK("request timeout %d", req_timeout_ms);

        test_conf_init(&conf, NULL, 60);

        mcluster = test_mock_cluster_new(1, &bootstraps);

        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        test_conf_set(conf, "bootstrap.servers", bootstraps);

        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        q = rd_kafka_queue_get_main(rk);

        if (req_timeout_ms > 0) {
                /* Admin options */
                options = rd_kafka_AdminOptions_new(
                    rk, RD_KAFKA_ADMIN_OP_ALTERCONSUMERGROUPOFFSETS);
                TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
                    options, req_timeout_ms, errstr, sizeof(errstr)));
        }


        for (i = 0; i < TEST_ERR_SIZE; i++) {
                /* Offsets to alter */
                to_alter = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(to_alter, topic, 0)->offset =
                    3;
                cgoffsets =
                    rd_kafka_AlterConsumerGroupOffsets_new(group_id, to_alter);

                TEST_SAY("Call AlterConsumerGroupOffsets, err %s\n",
                         rd_kafka_err2name(errs[i]));
                rd_kafka_mock_push_request_errors(
                    mcluster, RD_KAFKAP_OffsetCommit, 1, errs[i]);
                rd_kafka_AlterConsumerGroupOffsets(rk, &cgoffsets, 1, options,
                                                   q);

                rd_kafka_topic_partition_list_destroy(to_alter);
                rd_kafka_AlterConsumerGroupOffsets_destroy(cgoffsets);

                TEST_SAY("AlterConsumerGroupOffsets.queue_poll, err %s\n",
                         rd_kafka_err2name(errs[i]));
                /* Poll result queue for AlterConsumerGroupOffsets result.
                 * Print but otherwise ignore other event types
                 * (typically generic Error events). */
                while (1) {
                        rkev = rd_kafka_queue_poll(q, tmout_multip(10 * 1000));
                        TEST_SAY("AlterConsumerGroupOffsets: got %s\n",
                                 rd_kafka_event_name(rkev));
                        if (rkev == NULL)
                                continue;
                        if (rd_kafka_event_error(rkev))
                                TEST_SAY("%s: %s\n", rd_kafka_event_name(rkev),
                                         rd_kafka_event_error_string(rkev));

                        if (rd_kafka_event_type(rkev) ==
                            RD_KAFKA_EVENT_ALTERCONSUMERGROUPOFFSETS_RESULT)
                                break;

                        rd_kafka_event_destroy(rkev);
                }

                /* Convert event to proper result */
                res = rd_kafka_event_AlterConsumerGroupOffsets_result(rkev);
                TEST_ASSERT(res,
                            "expected AlterConsumerGroupOffsets_result, not %s",
                            rd_kafka_event_name(rkev));

                gres = rd_kafka_AlterConsumerGroupOffsets_result_groups(
                    res, &gres_cnt);
                TEST_ASSERT(gres && gres_cnt == 1,
                            "expected gres_cnt == 1, not %" PRIusz, gres_cnt);

                partitions = rd_kafka_group_result_partitions(gres[0]);

                /* Verify expected errors */
                for (j = 0; j < partitions->cnt; j++) {
                        rd_kafka_topic_partition_t *rktpar =
                            &partitions->elems[j];
                        TEST_ASSERT_LATER(rktpar->err == errs[i],
                                          "Result %s [%" PRId32
                                          "] has error %s, "
                                          "expected %s",
                                          topic, 0,
                                          rd_kafka_err2name(rktpar->err),
                                          rd_kafka_err2name(errs[i]));
                }

                rd_kafka_event_destroy(rkev);
        }
        if (options)
                rd_kafka_AdminOptions_destroy(options);

        rd_kafka_queue_destroy(q);

        rd_kafka_destroy(rk);

        test_mock_cluster_destroy(mcluster);

        TEST_LATER_CHECK();

        SUB_TEST_PASS();

#undef TEST_ERR_SIZE
}

/**
 * @brief A leader change should remove metadata cache for a topic
 *        queried in ListOffsets.
 */
static void do_test_ListOffsets_leader_change(void) {
        size_t cnt;
        rd_kafka_conf_t *conf;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        const char *topic = "test";
        rd_kafka_t *rk;
        rd_kafka_queue_t *q;
        rd_kafka_topic_partition_list_t *to_list;
        rd_kafka_event_t *rkev;
        rd_kafka_resp_err_t err;
        const rd_kafka_ListOffsets_result_t *result;
        const rd_kafka_ListOffsetsResultInfo_t **result_infos;

        test_conf_init(&conf, NULL, 60);

        mcluster = test_mock_cluster_new(2, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 2);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        test_conf_set(conf, "bootstrap.servers", bootstraps);

        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        q = rd_kafka_queue_get_main(rk);

        to_list = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(to_list, topic, 0)->offset = -1;

        TEST_SAY("First ListOffsets call to leader broker 1\n");
        rd_kafka_ListOffsets(rk, to_list, NULL, q);

        rkev = rd_kafka_queue_poll(q, -1);

        TEST_ASSERT(rd_kafka_event_type(rkev) ==
                        RD_KAFKA_EVENT_LISTOFFSETS_RESULT,
                    "Expected LISTOFFSETS_RESULT event type, got %d",
                    rd_kafka_event_type(rkev));

        TEST_CALL_ERR__(rd_kafka_event_error(rkev));

        rd_kafka_event_destroy(rkev);


        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2);

        TEST_SAY(
            "Second ListOffsets call to leader broker 1, returns "
            "NOT_LEADER_OR_FOLLOWER"
            " and invalidates cache\n");
        rd_kafka_ListOffsets(rk, to_list, NULL, q);

        rkev         = rd_kafka_queue_poll(q, -1);
        result       = rd_kafka_event_ListOffsets_result(rkev);
        result_infos = rd_kafka_ListOffsets_result_infos(result, &cnt);

        TEST_ASSERT(cnt == 1, "Result topic cnt should be 1, got %" PRIusz,
                    cnt);
        err = rd_kafka_ListOffsetsResultInfo_topic_partition(result_infos[0])
                  ->err;
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER,
                    "Expected event error NOT_LEADER_OR_FOLLOWER, got %s",
                    rd_kafka_err2name(err));

        rd_kafka_event_destroy(rkev);

        TEST_SAY(
            "Third ListOffsets call to leader broker 2, returns NO_ERROR\n");
        rd_kafka_ListOffsets(rk, to_list, NULL, q);

        rkev         = rd_kafka_queue_poll(q, -1);
        result       = rd_kafka_event_ListOffsets_result(rkev);
        result_infos = rd_kafka_ListOffsets_result_infos(result, &cnt);

        TEST_ASSERT(cnt == 1, "Result topic cnt should be 1, got %" PRIusz,
                    cnt);
        err = rd_kafka_ListOffsetsResultInfo_topic_partition(result_infos[0])
                  ->err;
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected event error NO_ERROR, got %s",
                    rd_kafka_err2name(err));

        rd_kafka_event_destroy(rkev);

        rd_kafka_topic_partition_list_destroy(to_list);
        rd_kafka_queue_destroy(q);
        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);
}

int main_0138_admin_mock(int argc, char **argv) {

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_AlterConsumerGroupOffsets_errors(-1);
        do_test_AlterConsumerGroupOffsets_errors(1000);

        do_test_ListOffsets_leader_change();

        return 0;
}
