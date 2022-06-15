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
#include "rdkafka.h"  /* for Kafka driver */



static void do_legacy_seek (const char *topic, uint64_t testid, int msg_cnt) {
        rd_kafka_t *rk_c;
	rd_kafka_topic_t *rkt_c;
	int32_t partition = 0;
	int i;
	int64_t offset_last, offset_base;
	int dance_iterations = 10;
	int msgs_per_dance = 10;
        const int msg_base = 0;

        SUB_TEST_QUICK();

	rk_c = test_create_consumer(NULL, NULL, NULL, NULL);
	rkt_c = test_create_consumer_topic(rk_c, topic);

	/* Start consumer tests */
	test_consumer_start("verify.all", rkt_c, partition,
                            RD_KAFKA_OFFSET_BEGINNING);
	/* Make sure all messages are available */
	offset_last = test_consume_msgs("verify.all", rkt_c,
                                        testid, partition, TEST_NO_SEEK,
                                        msg_base, msg_cnt, 1/* parse format*/);

	/* Rewind offset back to its base. */
	offset_base = offset_last - msg_cnt + 1;

	TEST_SAY("%s [%"PRId32"]: Do random seek&consume for msgs #%d+%d with "
		 "offsets %"PRId64"..%"PRId64"\n",
		 rd_kafka_topic_name(rkt_c), partition,
		 msg_base, msg_cnt, offset_base, offset_last);

	/* Now go dancing over the entire range with offset seeks. */
	for (i = 0 ; i < dance_iterations ; i++) {
		int64_t offset = jitter((int)offset_base,
					(int)offset_base+msg_cnt);

		test_consume_msgs("dance", rkt_c,
                                  testid, partition, offset,
                                  msg_base + (int)(offset - offset_base),
                                  RD_MIN(msgs_per_dance,
					 (int)(offset_last - offset)),
				  1 /* parse format */);
	}

	test_consumer_stop("1", rkt_c, partition);

	rd_kafka_topic_destroy(rkt_c);
	rd_kafka_destroy(rk_c);

        SUB_TEST_PASS();
}


static void do_seek (const char *topic, uint64_t testid,
                     int msg_cnt, rd_bool_t with_timeout) {
        rd_kafka_t *c;
        rd_kafka_topic_partition_list_t *partitions;
        char errstr[512];
        int i;

        SUB_TEST_QUICK("%s timeout", with_timeout ? "with" : "without");

        c = test_create_consumer(topic, NULL, NULL, NULL);

        partitions = rd_kafka_topic_partition_list_new(3);
        for (i = 0 ; i < 3 ; i++)
                rd_kafka_topic_partition_list_add(partitions, topic, i)->
                        offset = RD_KAFKA_OFFSET_END;

        TEST_CALL__(rd_kafka_assign(c, partitions));

        /* Should see no messages */
        test_consumer_poll_no_msgs("NO.MSGS", c, testid, 3000);

        /* Seek to beginning */
        for (i = 0 ; i < 3 ; i++) {
                /* Sentinel to verify that this field is reset by
                 * seek_partitions() */
                partitions->elems[i].err = RD_KAFKA_RESP_ERR__BAD_MSG;
                partitions->elems[i].offset = i == 0 ?
                        /* Logical and absolute offsets for the same thing */
                        RD_KAFKA_OFFSET_BEGINNING : 0;
        }

        TEST_SAY("Seeking\n");
        TEST_CALL_ERROR__(rd_kafka_seek_partitions(c, partitions,
                                                   with_timeout ? 7000 : -1));

        /* Verify that there are no per-partition errors */
        for (i = 0 ; i < 3 ; i++)
                TEST_ASSERT_LATER(!partitions->elems[i].err,
                                  "Partition #%d has unexpected error: %s",
                                  i,
                                  rd_kafka_err2name(partitions->elems[i].err));
        TEST_LATER_CHECK();

        rd_kafka_topic_partition_list_destroy(partitions);

        /* Should now see all messages */
        test_consumer_poll("MSGS", c, testid, -1, 0, msg_cnt, NULL);

        /* Some close/destroy variation */
        if (with_timeout)
                test_consumer_close(c);

        rd_kafka_destroy(c);

        SUB_TEST_PASS();
}


int main_0015_offsets_seek (int argc, char **argv) {
        const char *topic = test_mk_topic_name("0015", 1);
        int msg_cnt_per_part = test_quick ? 100 : 1000;
        int msg_cnt = 3 * msg_cnt_per_part;
        uint64_t testid;

        testid = test_id_generate();

        test_produce_msgs_easy_multi(
                testid,
                topic, 0, 0*msg_cnt_per_part, msg_cnt_per_part,
                topic, 1, 1*msg_cnt_per_part, msg_cnt_per_part,
                topic, 2, 2*msg_cnt_per_part, msg_cnt_per_part,
                NULL);

        /* legacy seek: only reads partition 0 */
        do_legacy_seek(topic, testid, msg_cnt_per_part);

        do_seek(topic, testid, msg_cnt, rd_true/*with timeout*/);

        do_seek(topic, testid, msg_cnt, rd_true/*without timeout*/);

        return 0;
}
