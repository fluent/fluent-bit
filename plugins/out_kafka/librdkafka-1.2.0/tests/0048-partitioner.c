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
#include "rdkafka.h"

#include <stdarg.h>

/**
 * Various partitioner tests
 *
 * - Issue #797 - deadlock on failed partitioning
 * - Verify that partitioning works across partitioners.
 */

int32_t my_invalid_partitioner (const rd_kafka_topic_t *rkt,
				const void *keydata, size_t keylen,
				int32_t partition_cnt,
				void *rkt_opaque,
				void *msg_opaque) {
	int32_t partition = partition_cnt + 10;
	TEST_SAYL(4, "partition \"%.*s\" to %"PRId32"\n",
		 (int)keylen, (const char *)keydata, partition);
	return partition;
}


/* FIXME: This doesn't seem to trigger the bug in #797.
 *        Still a useful test though. */
static void do_test_failed_partitioning (void) {
	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;
	rd_kafka_topic_conf_t *tconf;
	const char *topic = test_mk_topic_name(__FUNCTION__, 1);
	int i;
        int msgcnt = test_quick ? 100 : 10000;

	test_conf_init(NULL, &tconf, 0);

	rk = test_create_producer();
	rd_kafka_topic_conf_set_partitioner_cb(tconf, my_invalid_partitioner);
	test_topic_conf_set(tconf, "message.timeout.ms",
                            tsprintf("%d", tmout_multip(10000)));
	rkt = rd_kafka_topic_new(rk, topic, tconf);
	TEST_ASSERT(rkt != NULL, "%s", rd_kafka_err2str(rd_kafka_last_error()));

	/* Produce some messages (to p 0) to create topic */
	test_produce_msgs(rk, rkt, 0, 0, 0, 1, NULL, 0);

	/* Now use partitioner */
	for (i = 0 ; i < msgcnt ; i++) {
		rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;
		if (rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA,
				     0, NULL, 0, NULL, 0, NULL) == -1)
			err = rd_kafka_last_error();
		if (err != RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION)
			TEST_FAIL("produce(): "
				  "Expected UNKNOWN_PARTITION, got %s\n",
				  rd_kafka_err2str(err));
	}
	test_flush(rk, 5000);

	rd_kafka_topic_destroy(rkt);
	rd_kafka_destroy(rk);
}


static void part_dr_msg_cb (rd_kafka_t *rk,
                            const rd_kafka_message_t *rkmessage, void *opaque) {
        int32_t *partp = rkmessage->_private;
        int *remainsp = opaque;

        if (rkmessage->err) {
                /* Will fail later */
                TEST_WARN("Delivery failed: %s\n",
                          rd_kafka_err2str(rkmessage->err));
                *partp = -1;
        } else {
                *partp = rkmessage->partition;
        }

        (*remainsp)--;
}

/**
 * @brief Test single \p partitioner
 */
static void do_test_partitioner (const char *topic, const char *partitioner,
                                 int msgcnt, const char **keys,
                                 const int32_t *exp_part) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        int i;
        int32_t *parts;
        int remains = msgcnt;
        int randcnt = 0;
        int fails = 0;

        TEST_SAY(_C_MAG "Test partitioner \"%s\"\n", partitioner);

        test_conf_init(&conf, NULL, 30);
        rd_kafka_conf_set_opaque(conf, &remains);
        rd_kafka_conf_set_dr_msg_cb(conf, part_dr_msg_cb);
        test_conf_set(conf, "partitioner", partitioner);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        parts = malloc(msgcnt * sizeof(*parts));
        for (i = 0 ; i < msgcnt ; i++)
                parts[i] = -1;

        /*
         * Produce messages
         */
        for (i = 0 ; i < msgcnt ; i++) {
                rd_kafka_resp_err_t err;

                err = rd_kafka_producev(rk,
                                        RD_KAFKA_V_TOPIC(topic),
                                        RD_KAFKA_V_KEY(keys[i],
                                                       keys[i] ?
                                                       strlen(keys[i]) : 0),
                                        RD_KAFKA_V_OPAQUE(&parts[i]),
                                        RD_KAFKA_V_END);
                TEST_ASSERT(!err,
                            "producev() failed: %s", rd_kafka_err2str(err));

                randcnt += exp_part[i] == -1;
        }

        rd_kafka_flush(rk, tmout_multip(10000));

        TEST_ASSERT(remains == 0,
                    "Expected remains=%d, not %d for %d messages",
                    0, remains, msgcnt);

        /*
         * Verify produced partitions to expected partitions.
         */

        /* First look for produce failures */
        for (i = 0 ; i < msgcnt ; i++) {
                if (parts[i] == -1) {
                        TEST_WARN("Message #%d (exp part %"PRId32") "
                                  "was not successfully produced\n",
                                  i, exp_part[i]);
                        fails++;
                }
        }

        TEST_ASSERT(!fails, "See %d previous failure(s)", fails);


        if (randcnt == msgcnt) {
                /* If all expected partitions are random make sure
                 * the produced partitions have some form of
                 * random distribution */
                int32_t last_part = parts[0];
                int samecnt = 0;

                for (i = 0 ; i < msgcnt ; i++) {
                        samecnt += parts[i] == last_part;
                        last_part = parts[i];
                }

                TEST_ASSERT(samecnt < msgcnt,
                            "No random distribution, all on partition %"PRId32,
                            last_part);
        } else {
                for (i = 0 ; i < msgcnt ; i++) {
                        if (exp_part[i] != -1 &&
                            parts[i] != exp_part[i]) {
                                TEST_WARN("Message #%d expected partition "
                                          "%"PRId32" but got %"PRId32": %s\n",
                                          i, exp_part[i], parts[i],
                                          keys[i]);
                                fails++;
                        }
                }


                TEST_ASSERT(!fails, "See %d previous failure(s)", fails);
        }

        free(parts);

        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "Test partitioner \"%s\": PASS\n", partitioner);
}

extern uint32_t rd_crc32 (const char *, size_t);

/**
 * @brief Test all builtin partitioners
 */
static void do_test_partitioners (void) {
        int part_cnt = test_quick ? 7 : 17;
#define _MSG_CNT 5
        const char *unaligned = "123456";
        /* Message keys */
        const char *keys[_MSG_CNT] = {
                NULL,
                "", // empty
                unaligned+1,
                "this is another string with more length to it perhaps",
                "hejsan"
        };
        struct {
                const char *partitioner;
                /* Expected partition per message (see keys above) */
                int32_t exp_part[_MSG_CNT];
        } ptest[] = {
                { "random", { -1, -1, -1, -1, -1 } },
                { "consistent", {
                                /* These constants were acquired using
                                 * the 'crc32' command on OSX */
                                0x0 % part_cnt,
                                0x0 % part_cnt,
                                0xb1b451d7 % part_cnt,
                                0xb0150df7 % part_cnt,
                                0xd077037e % part_cnt
                        } },
                { "consistent_random", {
                                -1,
                                -1,
                                0xb1b451d7 % part_cnt,
                                0xb0150df7 % part_cnt,
                                0xd077037e % part_cnt
                        } },
                { "murmur2", {
                                /* .. using tests/java/Murmur2Cli */
                                0x106e08d9 % part_cnt,
                                0x106e08d9 % part_cnt,
                                0x058d780f % part_cnt,
                                0x4f7703da % part_cnt,
                                0x5ec19395 % part_cnt
                        } },
                { "murmur2_random", {
                                -1,
                                0x106e08d9 % part_cnt,
                                0x058d780f % part_cnt,
                                0x4f7703da % part_cnt,
                                0x5ec19395 % part_cnt
                        } },
                { NULL }
        };
        int pi;
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);

        test_create_topic(NULL, topic, part_cnt, 1);

        for (pi = 0 ; ptest[pi].partitioner ; pi++) {
                do_test_partitioner(topic, ptest[pi].partitioner,
                                    _MSG_CNT, keys, ptest[pi].exp_part);
        }
}

int main_0048_partitioner (int argc, char **argv) {
        if (test_can_create_topics(0))
                do_test_partitioners();
	do_test_failed_partitioning();
	return 0;
}
