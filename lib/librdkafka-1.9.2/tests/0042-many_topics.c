/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
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

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


/**
 * #781: handle many (?) topics.
 */


const int msgs_per_topic = 100;


/**
 * Request offset for nonexisting partition.
 * Will cause rd_kafka_destroy() to hang.
 */



static void produce_many(char **topics, int topic_cnt, uint64_t testid) {
        rd_kafka_t *rk;
        test_timing_t t_rkt_create;
        int i;
        rd_kafka_topic_t **rkts;

        TEST_SAY(_C_MAG "%s\n" _C_CLR, __FUNCTION__);

        rk = test_create_producer();

        TEST_SAY("Creating %d topic objects\n", topic_cnt);

        rkts = malloc(sizeof(*rkts) * topic_cnt);
        TIMING_START(&t_rkt_create, "Topic object create");
        for (i = 0; i < topic_cnt; i++) {
                rkts[i] = test_create_topic_object(rk, topics[i], "acks", "all",
                                                   NULL);
        }
        TIMING_STOP(&t_rkt_create);

        TEST_SAY("Producing %d messages to each %d topics\n", msgs_per_topic,
                 topic_cnt);
        /* Produce messages to each topic (so they are created) */
        for (i = 0; i < topic_cnt; i++) {
                test_produce_msgs(rk, rkts[i], testid, 0, i * msgs_per_topic,
                                  msgs_per_topic, NULL, 100);
        }

        TEST_SAY("Destroying %d topic objects\n", topic_cnt);
        for (i = 0; i < topic_cnt; i++) {
                rd_kafka_topic_destroy(rkts[i]);
        }
        free(rkts);

        test_flush(rk, 30000);

        rd_kafka_destroy(rk);
}


static void legacy_consume_many(char **topics, int topic_cnt, uint64_t testid) {
        rd_kafka_t *rk;
        test_timing_t t_rkt_create;
        int i;
        rd_kafka_topic_t **rkts;
        int msg_base = 0;

        TEST_SAY(_C_MAG "%s\n" _C_CLR, __FUNCTION__);

        test_conf_init(NULL, NULL, 60);

        rk = test_create_consumer(NULL, NULL, NULL, NULL);

        TEST_SAY("Creating %d topic objects\n", topic_cnt);

        rkts = malloc(sizeof(*rkts) * topic_cnt);
        TIMING_START(&t_rkt_create, "Topic object create");
        for (i = 0; i < topic_cnt; i++)
                rkts[i] = test_create_topic_object(rk, topics[i], NULL);
        TIMING_STOP(&t_rkt_create);

        TEST_SAY("Start consumer for %d topics\n", topic_cnt);
        for (i = 0; i < topic_cnt; i++)
                test_consumer_start("legacy", rkts[i], 0,
                                    RD_KAFKA_OFFSET_BEGINNING);

        TEST_SAY("Consuming from %d messages from each %d topics\n",
                 msgs_per_topic, topic_cnt);
        for (i = 0; i < topic_cnt; i++) {
                test_consume_msgs("legacy", rkts[i], testid, 0, TEST_NO_SEEK,
                                  msg_base, msgs_per_topic, 1);
                msg_base += msgs_per_topic;
        }

        TEST_SAY("Stopping consumers\n");
        for (i = 0; i < topic_cnt; i++)
                test_consumer_stop("legacy", rkts[i], 0);


        TEST_SAY("Destroying %d topic objects\n", topic_cnt);
        for (i = 0; i < topic_cnt; i++)
                rd_kafka_topic_destroy(rkts[i]);

        free(rkts);

        rd_kafka_destroy(rk);
}



static void
subscribe_consume_many(char **topics, int topic_cnt, uint64_t testid) {
        rd_kafka_t *rk;
        int i;
        rd_kafka_topic_conf_t *tconf;
        rd_kafka_topic_partition_list_t *parts;
        rd_kafka_resp_err_t err;
        test_msgver_t mv;

        TEST_SAY(_C_MAG "%s\n" _C_CLR, __FUNCTION__);

        test_conf_init(NULL, &tconf, 60);
        test_topic_conf_set(tconf, "auto.offset.reset", "earliest");
        rk = test_create_consumer(__FUNCTION__, NULL, NULL, tconf);

        parts = rd_kafka_topic_partition_list_new(topic_cnt);
        for (i = 0; i < topic_cnt; i++)
                rd_kafka_topic_partition_list_add(parts, topics[i],
                                                  RD_KAFKA_PARTITION_UA);

        TEST_SAY("Subscribing to %d topics\n", topic_cnt);
        err = rd_kafka_subscribe(rk, parts);
        if (err)
                TEST_FAIL("subscribe() failed: %s\n", rd_kafka_err2str(err));

        rd_kafka_topic_partition_list_destroy(parts);

        test_msgver_init(&mv, testid);
        test_consumer_poll("consume.subscribe", rk, testid, -1, 0,
                           msgs_per_topic * topic_cnt, &mv);

        for (i = 0; i < topic_cnt; i++)
                test_msgver_verify_part("subscribe", &mv, TEST_MSGVER_ALL_PART,
                                        topics[i], 0, i * msgs_per_topic,
                                        msgs_per_topic);
        test_msgver_clear(&mv);

        test_consumer_close(rk);

        rd_kafka_destroy(rk);
}



static void assign_consume_many(char **topics, int topic_cnt, uint64_t testid) {
        rd_kafka_t *rk;
        rd_kafka_topic_partition_list_t *parts;
        int i;
        test_msgver_t mv;

        TEST_SAY(_C_MAG "%s\n" _C_CLR, __FUNCTION__);

        test_conf_init(NULL, NULL, 60);
        rk = test_create_consumer(__FUNCTION__, NULL, NULL, NULL);

        parts = rd_kafka_topic_partition_list_new(topic_cnt);
        for (i = 0; i < topic_cnt; i++)
                rd_kafka_topic_partition_list_add(parts, topics[i], 0)->offset =
                    RD_KAFKA_OFFSET_TAIL(msgs_per_topic);

        test_consumer_assign("consume.assign", rk, parts);
        rd_kafka_topic_partition_list_destroy(parts);

        test_msgver_init(&mv, testid);
        test_consumer_poll("consume.assign", rk, testid, -1, 0,
                           msgs_per_topic * topic_cnt, &mv);

        for (i = 0; i < topic_cnt; i++)
                test_msgver_verify_part("assign", &mv, TEST_MSGVER_ALL_PART,
                                        topics[i], 0, i * msgs_per_topic,
                                        msgs_per_topic);
        test_msgver_clear(&mv);

        test_consumer_close(rk);

        rd_kafka_destroy(rk);
}



int main_0042_many_topics(int argc, char **argv) {
        char **topics;
        int topic_cnt = test_quick ? 4 : 20; /* up this as needed,
                                              * topic creation takes time so
                                              * unless hunting a bug
                                              * we keep this low to keep the
                                              * test suite run time down. */
        uint64_t testid;
        int i;

        test_conf_init(NULL, NULL, 60);

        testid = test_id_generate();

        /* Generate unique topic names */
        topics = malloc(sizeof(*topics) * topic_cnt);
        for (i = 0; i < topic_cnt; i++)
                topics[i] = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));

        produce_many(topics, topic_cnt, testid);
        legacy_consume_many(topics, topic_cnt, testid);
        if (test_broker_version >= TEST_BRKVER(0, 9, 0, 0)) {
                subscribe_consume_many(topics, topic_cnt, testid);
                assign_consume_many(topics, topic_cnt, testid);
        }

        for (i = 0; i < topic_cnt; i++)
                free(topics[i]);
        free(topics);

        return 0;
}
