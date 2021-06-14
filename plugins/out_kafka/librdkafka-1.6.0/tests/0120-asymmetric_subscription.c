/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020, Magnus Edenhill
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


#define _PART_CNT 4


/**
 * @brief Verify proper assignment for asymmetrical subscriptions.
 */
static void do_test_asymmetric (const char *assignor, const char *bootstraps) {
        rd_kafka_conf_t *conf;
#define _C_CNT 3
        rd_kafka_t *c[_C_CNT];
#define _S_CNT 2  /* max subscription count per consumer */
        const char *topics[_C_CNT][_S_CNT] = {
                /* c0 */ { "t1", "t2" },
                /* c1 */ { "t2", "t3" },
                /* c2 */ { "t4" },
        };
        struct {
                const char *topic;
                const int cnt;
                int seen;
        } expect[_C_CNT][_S_CNT] = {
                /* c0 */
                {
                        { "t1", _PART_CNT },
                        { "t2", _PART_CNT/2 },
                },
                /* c1 */
                {
                        { "t2", _PART_CNT/2 },
                        { "t3", _PART_CNT },
                },
                /* c2 */
                {
                        { "t4", _PART_CNT },
                },
        };
        const char *groupid = assignor;
        int i;

        SUB_TEST_QUICK("%s assignor", assignor);

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "partition.assignment.strategy", assignor);

        for (i = 0 ; i < _C_CNT ; i++) {
                char name[16];
                rd_kafka_topic_partition_list_t *tlist =
                        rd_kafka_topic_partition_list_new(2);
                int j;

                rd_snprintf(name, sizeof(name), "c%d", i);
                test_conf_set(conf, "client.id", name);

                for (j = 0 ; j < _S_CNT && topics[i][j] ; j++)
                        rd_kafka_topic_partition_list_add(
                                tlist, topics[i][j], RD_KAFKA_PARTITION_UA);

                c[i] = test_create_consumer(groupid, NULL,
                                            rd_kafka_conf_dup(conf), NULL);

                TEST_CALL_ERR__(rd_kafka_subscribe(c[i], tlist));

                rd_kafka_topic_partition_list_destroy(tlist);
        }

        rd_kafka_conf_destroy(conf);


        /* Await assignments for all consumers */
        for (i = 0 ; i < _C_CNT ; i++)
                test_consumer_wait_assignment(c[i]);

        /* All have assignments, grab them. */
        for (i = 0 ; i < _C_CNT ; i++) {
                int j;
                int p;
                rd_kafka_topic_partition_list_t *assignment;

                TEST_CALL_ERR__(rd_kafka_assignment(c[i], &assignment));

                TEST_ASSERT(assignment, "No assignment for %s",
                            rd_kafka_name(c[i]));

                for (p = 0 ; p < assignment->cnt ; p++) {
                        const rd_kafka_topic_partition_t *part =
                                &assignment->elems[p];
                        rd_bool_t found = rd_false;

                        for (j = 0 ; j < _S_CNT && expect[i][j].topic ; j++) {
                                if (!strcmp(part->topic, expect[i][j].topic)) {
                                        expect[i][j].seen++;
                                        found = rd_true;
                                        break;
                                }
                        }

                        TEST_ASSERT(found,
                                    "%s was assigned unexpected topic %s",
                                    rd_kafka_name(c[i]), part->topic);

                }

                for (j = 0 ; j < _S_CNT && expect[i][j].topic ; j++) {
                        TEST_ASSERT(expect[i][j].seen == expect[i][j].cnt,
                                    "%s expected %d assigned partitions "
                                    "for %s, not %d",
                                    rd_kafka_name(c[i]),
                                    expect[i][j].cnt,
                                    expect[i][j].topic,
                                    expect[i][j].seen);
                }

                rd_kafka_topic_partition_list_destroy(assignment);
        }


        for (i = 0 ; i < _C_CNT ; i++) {
                if (strcmp(assignor, "range") && (i & 1) == 0)
                        test_consumer_close(c[i]);
                rd_kafka_destroy(c[i]);
        }


        SUB_TEST_PASS();
}


int main_0120_asymmetric_subscription (int argc, char **argv) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        mcluster = test_mock_cluster_new(3, &bootstraps);


        /* Create topics */
        rd_kafka_mock_topic_create(mcluster, "t1", _PART_CNT, 1);
        rd_kafka_mock_topic_create(mcluster, "t2", _PART_CNT, 1);
        rd_kafka_mock_topic_create(mcluster, "t3", _PART_CNT, 1);
        rd_kafka_mock_topic_create(mcluster, "t4", _PART_CNT, 1);


        do_test_asymmetric("roundrobin", bootstraps);
        do_test_asymmetric("range", bootstraps);
        do_test_asymmetric("cooperative-sticky", bootstraps);

        test_mock_cluster_destroy(mcluster);

        return 0;
}
