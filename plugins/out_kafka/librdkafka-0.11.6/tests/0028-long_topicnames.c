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


/**
 * Test long topic names (>=255 characters), issue #529.
 * This broker-side issue only seems to occur when explicitly creating
 * topics with kafka-topics.sh --create, not with auto-created topics.
 */


int main_0028_long_topicnames (int argc, char **argv) {
        const int msgcnt = 1000;
        uint64_t testid;
	char topic[256];
	rd_kafka_t *rk_c;

	if (!test_can_create_topics(1))
		return 0;

	memset(topic, 'a', sizeof(topic)-1);
	topic[sizeof(topic)-1] = '\0';

	strncpy(topic, test_mk_topic_name(topic, 1), sizeof(topic)-1);

	TEST_SAY("Using topic name of %d bytes: %s\n",
		 (int)strlen(topic), topic);

	/* Create topic */
	test_create_topic(topic, 1, 1);

	/* First try a non-verifying consumer. The consumer has been known
	 * to crash when the broker bug kicks in. */
	rk_c = test_create_consumer(topic, NULL, NULL, NULL);
	test_consumer_subscribe(rk_c, topic);
	test_consumer_poll_no_msgs("consume.nomsgs", rk_c, 0, 5000);
	test_consumer_close(rk_c);

        /* Produce messages */
        testid = test_produce_msgs_easy(topic, 0,
                                        RD_KAFKA_PARTITION_UA, msgcnt);

	/* Consume messages */
	test_consume_msgs_easy(NULL, topic, testid, -1, msgcnt, NULL);

        return 0;
}
