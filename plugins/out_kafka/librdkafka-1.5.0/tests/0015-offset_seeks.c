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




int main_0015_offsets_seek (int argc, char **argv) {
	const char *topic = test_mk_topic_name("0015", 1);
	rd_kafka_t *rk_p, *rk_c;
	rd_kafka_topic_t *rkt_p, *rkt_c;
        int msg_cnt = test_quick ? 100 : 1000;
	int msg_base = 0;
	int32_t partition = 0;
	int i;
	int64_t offset_last, offset_base;
	uint64_t testid;
	int dance_iterations = 10;
	int msgs_per_dance = 10;

	testid = test_id_generate();

	/* Produce messages */
	rk_p = test_create_producer();
	rkt_p = test_create_producer_topic(rk_p, topic, NULL);

	test_produce_msgs(rk_p, rkt_p, testid, partition, msg_base, msg_cnt,
			  NULL, 0);

	rd_kafka_topic_destroy(rkt_p);
	rd_kafka_destroy(rk_p);


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

	return 0;
}
