/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2018, Magnus Edenhill
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

/**
 * @name Test rd_kafka_destroy_flags()
 */


#include "test.h"


static RD_TLS int rebalance_cnt = 0;

static void destroy_flags_rebalance_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
                                        rd_kafka_topic_partition_list_t *parts,
                                        void *opaque) {
        rebalance_cnt++;

        TEST_SAY("rebalance_cb: %s with %d partition(s)\n",
                 rd_kafka_err2str(err), parts->cnt);

        switch (err)
        {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                test_consumer_assign("rebalance", rk, parts);
                break;

        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                test_consumer_unassign("rebalance", rk);
                break;

        default:
                TEST_FAIL("rebalance_cb: error: %s", rd_kafka_err2str(err));
        }
}

struct df_args {
        rd_kafka_type_t client_type;
        int produce_cnt;
        int consumer_subscribe;
        int consumer_unsubscribe;
};

static void do_test_destroy_flags (const char *topic,
                                   int destroy_flags,
                                   int local_mode,
                                   const struct df_args *args) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        test_timing_t t_destroy;

        TEST_SAY(_C_MAG "[ test destroy_flags 0x%x for client_type %d, "
                 "produce_cnt %d, subscribe %d, unsubscribe %d, "
                 "%s mode ]\n" _C_CLR,
                 destroy_flags, args->client_type,
                 args->produce_cnt, args->consumer_subscribe,
                 args->consumer_unsubscribe,
                 local_mode ? "local" : "broker");

        test_conf_init(&conf, NULL, 20);

        if (local_mode)
                test_conf_set(conf, "bootstrap.servers", "");

        if (args->client_type == RD_KAFKA_PRODUCER) {

                rk = test_create_handle(args->client_type, conf);

                if (args->produce_cnt > 0) {
                        rd_kafka_topic_t *rkt;
                        int msgcounter = 0;

                        rkt = test_create_producer_topic(rk, topic, NULL);
                        test_produce_msgs_nowait(rk, rkt, 0,
                                                 RD_KAFKA_PARTITION_UA,
                                                 0, args->produce_cnt,
                                                 NULL, 100, 0,
                                                 &msgcounter);
                        rd_kafka_topic_destroy(rkt);
                }

        } else {
                int i;

                TEST_ASSERT(args->client_type == RD_KAFKA_CONSUMER);

                rk = test_create_consumer(topic, destroy_flags_rebalance_cb,
                                          conf, NULL);

                if (args->consumer_subscribe) {
                        test_consumer_subscribe(rk, topic);

                        if (!local_mode) {
                                TEST_SAY("Waiting for assignment\n");
                                while (rebalance_cnt == 0)
                                        test_consumer_poll_once(rk, NULL, 1000);
                        }
                }

                for (i = 0 ; i < 5 ; i++)
                        test_consumer_poll_once(rk, NULL, 100);

                if (args->consumer_unsubscribe) {
                        /* Test that calling rd_kafka_unsubscribe immediately
                         * prior to rd_kafka_destroy_flags doesn't cause the
                         * latter to hang. */
                        TEST_SAY(_C_YEL"Calling rd_kafka_unsubscribe\n"_C_CLR);
                        rd_kafka_unsubscribe(rk);
                }
        }

        rebalance_cnt = 0;
        TEST_SAY(_C_YEL "Calling rd_kafka_destroy_flags(0x%x)\n" _C_CLR,
                 destroy_flags);
        TIMING_START(&t_destroy, "rd_kafka_destroy_flags(0x%x)", destroy_flags);
        rd_kafka_destroy_flags(rk, destroy_flags);
        TIMING_STOP(&t_destroy);

        if (destroy_flags & RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE)
                TIMING_ASSERT_LATER(&t_destroy, 0, 200);
        else
                TIMING_ASSERT_LATER(&t_destroy, 0, 1000);

        if (args->consumer_subscribe &&
            !(destroy_flags & RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE)) {
                if (!local_mode)
                        TEST_ASSERT(rebalance_cnt > 0,
                                    "expected final rebalance callback");
        } else
                TEST_ASSERT(rebalance_cnt == 0,
                            "expected no rebalance callbacks, got %d",
                            rebalance_cnt);

        TEST_SAY(_C_GRN "[ test destroy_flags 0x%x for client_type %d, "
                 "produce_cnt %d, subscribe %d, unsubscribe %d, "
                 "%s mode: PASS ]\n" _C_CLR,
                 destroy_flags, args->client_type,
                 args->produce_cnt, args->consumer_subscribe,
                 args->consumer_unsubscribe,
                 local_mode ? "local" : "broker");
}


/**
 * @brief Destroy with flags
 */
static void destroy_flags (int local_mode) {
        const struct df_args args[] = {
                { RD_KAFKA_PRODUCER, 0, 0, 0 },
                { RD_KAFKA_PRODUCER, test_quick ? 100 : 10000, 0, 0 },
                { RD_KAFKA_CONSUMER, 0, 1, 0 },
                { RD_KAFKA_CONSUMER, 0, 1, 1 },
                { RD_KAFKA_CONSUMER, 0, 0, 0 }
        };
        const int flag_combos[] = { 0,
                                    RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE };
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        const rd_bool_t can_subscribe =
                test_broker_version >= TEST_BRKVER(0,9,0,0);
        int i, j;

        for (i = 0 ; i < (int)RD_ARRAYSIZE(args) ; i++) {
                for (j = 0 ; j < (int)RD_ARRAYSIZE(flag_combos) ; j++) {
                        if (!can_subscribe &&
                            (args[i].consumer_subscribe ||
                             args[i].consumer_unsubscribe))
                                continue;
                        do_test_destroy_flags(topic,
                                              flag_combos[j],
                                              local_mode,
                                              &args[i]);
                }
        }

}



int main_0084_destroy_flags_local (int argc, char **argv) {
        destroy_flags(1/*no brokers*/);
        return 0;
}

int main_0084_destroy_flags (int argc, char **argv) {
        destroy_flags(0/*with brokers*/);
        return 0;
}
