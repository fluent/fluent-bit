/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2018, Magnus Edenhill
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
#include "rdkafka.h"

/**
 * Verify that long-processing consumer leaves the group during
 * processing.
 *
 * MO:
 *  - produce messages to a single partition topic.
 *  - create two consumers, c1 and c2.
 *  - process first message slowly (2 * max.poll.interval.ms)
 *  - verify in other consumer that group rebalances after max.poll.interval.ms
 *    and the partition is assigned to the other consumer.
 */



int main_0089_max_poll_interval(int argc, char **argv) {
        const char *topic = test_mk_topic_name("0089_max_poll_interval", 1);
        uint64_t testid;
        const int msgcnt = 10;
        rd_kafka_t *c[2];
        rd_kafka_conf_t *conf;
        int64_t ts_next[2]    = {0, 0};
        int64_t ts_exp_msg[2] = {0, 0};
        int cmsgcnt           = 0;
        int i;
        int bad = -1;

        testid = test_id_generate();

        test_create_topic(NULL, topic, 1, 1);

        test_produce_msgs_easy(topic, testid, -1, msgcnt);

        test_conf_init(&conf, NULL, 60);

        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "max.poll.interval.ms", "10000" /*10s*/);
        test_conf_set(conf, "auto.offset.reset", "earliest");

        c[0] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);
        c[1] = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(c[0], topic);
        test_consumer_subscribe(c[1], topic);

        while (1) {
                for (i = 0; i < 2; i++) {
                        int64_t now;
                        rd_kafka_message_t *rkm;

                        /* Consumer is "processing" */
                        if (ts_next[i] > test_clock())
                                continue;

                        rkm = rd_kafka_consumer_poll(c[i], 100);
                        if (!rkm)
                                continue;

                        if (rkm->err) {
                                TEST_WARN(
                                    "Consumer %d error: %s: "
                                    "ignoring\n",
                                    i, rd_kafka_message_errstr(rkm));
                                continue;
                        }

                        now = test_clock();

                        cmsgcnt++;

                        TEST_SAY(
                            "Consumer %d received message (#%d) "
                            "at offset %" PRId64 "\n",
                            i, cmsgcnt, rkm->offset);

                        if (ts_exp_msg[i]) {
                                /* This consumer is expecting a message
                                 * after a certain time, namely after the
                                 * rebalance following max.poll.. being
                                 * exceeded in the other consumer */
                                TEST_ASSERT(
                                    now > ts_exp_msg[i],
                                    "Consumer %d: did not expect "
                                    "message for at least %dms",
                                    i, (int)((ts_exp_msg[i] - now) / 1000));
                                TEST_ASSERT(
                                    now < ts_exp_msg[i] + 10000 * 1000,
                                    "Consumer %d: expected message "
                                    "within 10s, not after %dms",
                                    i, (int)((now - ts_exp_msg[i]) / 1000));
                                TEST_SAY(
                                    "Consumer %d: received message "
                                    "at offset %" PRId64 " after rebalance\n",
                                    i, rkm->offset);

                                rd_kafka_message_destroy(rkm);
                                goto done;

                        } else if (cmsgcnt == 1) {
                                /* Process this message for 20s */
                                ts_next[i] = now + (20000 * 1000);

                                /* Exp message on other consumer after
                                 * max.poll.interval.ms */
                                ts_exp_msg[i ^ 1] = now + (10000 * 1000);

                                /* This is the bad consumer */
                                bad = i;

                                TEST_SAY(
                                    "Consumer %d processing message at "
                                    "offset %" PRId64 "\n",
                                    i, rkm->offset);
                                rd_kafka_message_destroy(rkm);
                        } else {
                                rd_kafka_message_destroy(rkm);

                                TEST_FAIL(
                                    "Consumer %d did not expect "
                                    "a message",
                                    i);
                        }
                }
        }

done:

        TEST_ASSERT(bad != -1, "Bad consumer not set");

        /* Wait for error ERR__MAX_POLL_EXCEEDED on the bad consumer. */
        while (1) {
                rd_kafka_message_t *rkm;

                rkm = rd_kafka_consumer_poll(c[bad], 1000);
                TEST_ASSERT(rkm, "Expected consumer result within 1s");

                TEST_ASSERT(rkm->err, "Did not expect message on bad consumer");

                TEST_SAY("Consumer error: %s: %s\n",
                         rd_kafka_err2name(rkm->err),
                         rd_kafka_message_errstr(rkm));

                if (rkm->err == RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED) {
                        rd_kafka_message_destroy(rkm);
                        break;
                }

                rd_kafka_message_destroy(rkm);
        }


        for (i = 0; i < 2; i++)
                rd_kafka_destroy_flags(c[i],
                                       RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);
        return 0;
}
