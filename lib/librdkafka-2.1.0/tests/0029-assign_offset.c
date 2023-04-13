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
 * Consumer: make sure specifying offsets in assign() works.
 */


static const int msgcnt     = 100; /* per-partition msgcnt */
static const int partitions = 4;

/* method 1: lower half of partitions use fixed offset
 *           upper half uses END */
#define REB_METHOD_1 1
/* method 2: first two partitions: fixed offset,
 *           rest: INVALID (== stored == END)
 * issue #583 */
#define REB_METHOD_2 2
static int reb_method;

static void rebalance_cb(rd_kafka_t *rk,
                         rd_kafka_resp_err_t err,
                         rd_kafka_topic_partition_list_t *parts,
                         void *opaque) {
        int i;

        TEST_SAY("rebalance_cb: %s:\n", rd_kafka_err2str(err));
        test_print_partition_list(parts);

        if (parts->cnt < partitions)
                TEST_FAIL("rebalance_cb: Expected %d partitions, not %d",
                          partitions, parts->cnt);

        switch (err) {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                for (i = 0; i < parts->cnt; i++) {
                        if (i >= partitions) {
                                /* Dont assign() partitions we dont want. */
                                rd_kafka_topic_partition_list_del_by_idx(parts,
                                                                         i);
                                continue;
                        }

                        if (reb_method == REB_METHOD_1) {
                                if (i < partitions)
                                        parts->elems[i].offset = msgcnt / 2;
                                else
                                        parts->elems[i].offset =
                                            RD_KAFKA_OFFSET_END;
                        } else if (reb_method == REB_METHOD_2) {
                                if (i < 2)
                                        parts->elems[i].offset = msgcnt / 2;
                                else
                                        parts->elems[i].offset =
                                            RD_KAFKA_OFFSET_INVALID;
                        }
                }
                TEST_SAY("Use these offsets:\n");
                test_print_partition_list(parts);
                test_consumer_assign("HL.REBALANCE", rk, parts);
                break;

        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                test_consumer_unassign("HL.REBALANCE", rk);
                break;

        default:
                TEST_FAIL("rebalance_cb: error: %s", rd_kafka_err2str(err));
        }
}

int main_0029_assign_offset(int argc, char **argv) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        rd_kafka_topic_partition_list_t *parts;
        uint64_t testid;
        int i;
        test_timing_t t_simple, t_hl;
        test_msgver_t mv;

        test_conf_init(NULL, NULL, 20 + (test_session_timeout_ms * 3 / 1000));

        /* Produce X messages to Y partitions so we get a
         * nice seekable 0..X offset one each partition. */
        /* Produce messages */
        testid = test_id_generate();
        rk     = test_create_producer();
        rkt    = test_create_producer_topic(rk, topic, NULL);

        parts = rd_kafka_topic_partition_list_new(partitions);

        for (i = 0; i < partitions; i++) {
                test_produce_msgs(rk, rkt, testid, i, 0, msgcnt, NULL, 0);
                /* Set start offset */
                rd_kafka_topic_partition_list_add(parts, topic, i)->offset =
                    msgcnt / 2;
        }

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);


        /* Simple consumer */
        TIMING_START(&t_simple, "SIMPLE.CONSUMER");
        rk = test_create_consumer(topic, NULL, NULL, NULL);
        test_msgver_init(&mv, testid);
        test_consumer_assign("SIMPLE.ASSIGN", rk, parts);
        test_consumer_poll("SIMPLE.CONSUME", rk, testid, -1, 0,
                           partitions * (msgcnt / 2), &mv);
        for (i = 0; i < partitions; i++)
                test_msgver_verify_part("HL.MSGS", &mv, TEST_MSGVER_ALL_PART,
                                        topic, i, msgcnt / 2, msgcnt / 2);
        test_msgver_clear(&mv);
        test_consumer_close(rk);
        rd_kafka_destroy(rk);
        TIMING_STOP(&t_simple);

        rd_kafka_topic_partition_list_destroy(parts);


        /* High-level consumer: method 1
         * Offsets are set in rebalance callback. */
        if (test_broker_version >= TEST_BRKVER(0, 9, 0, 0)) {
                reb_method = REB_METHOD_1;
                TIMING_START(&t_hl, "HL.CONSUMER");
                test_msgver_init(&mv, testid);
                rk = test_create_consumer(topic, rebalance_cb, NULL, NULL);
                test_consumer_subscribe(rk, topic);
                test_consumer_poll("HL.CONSUME", rk, testid, -1, 0,
                                   partitions * (msgcnt / 2), &mv);
                for (i = 0; i < partitions; i++)
                        test_msgver_verify_part("HL.MSGS", &mv,
                                                TEST_MSGVER_ALL_PART, topic, i,
                                                msgcnt / 2, msgcnt / 2);
                test_msgver_clear(&mv);
                test_consumer_close(rk);
                rd_kafka_destroy(rk);
                TIMING_STOP(&t_hl);


                /* High-level consumer: method 2:
                 * first two partitions are with fixed absolute offset, rest are
                 * auto offset (stored, which is now at end).
                 * Offsets are set in rebalance callback. */
                reb_method = REB_METHOD_2;
                TIMING_START(&t_hl, "HL.CONSUMER2");
                test_msgver_init(&mv, testid);
                rk = test_create_consumer(topic, rebalance_cb, NULL, NULL);
                test_consumer_subscribe(rk, topic);
                test_consumer_poll("HL.CONSUME2", rk, testid, partitions, 0,
                                   2 * (msgcnt / 2), &mv);
                for (i = 0; i < partitions; i++) {
                        if (i < 2)
                                test_msgver_verify_part(
                                    "HL.MSGS2.A", &mv, TEST_MSGVER_ALL_PART,
                                    topic, i, msgcnt / 2, msgcnt / 2);
                }
                test_msgver_clear(&mv);
                test_consumer_close(rk);
                rd_kafka_destroy(rk);
                TIMING_STOP(&t_hl);
        }

        return 0;
}
