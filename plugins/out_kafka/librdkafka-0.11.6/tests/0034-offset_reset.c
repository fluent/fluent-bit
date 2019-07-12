/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2016, Magnus Edenhill
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
 * Issue #559: make sure auto.offset.reset works with invalid offsets.
 */


static void do_test_reset (const char *topic, int partition,
			   const char *reset, int64_t initial_offset,
			   int exp_eofcnt, int exp_msgcnt, int exp_errcnt) {
	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;
	int eofcnt = 0, msgcnt = 0, errcnt = 0;

	TEST_SAY("Test auto.offset.reset=%s, "
		 "expect %d msgs, %d EOFs, %d errors\n",
		 reset, exp_msgcnt, exp_eofcnt, exp_errcnt);

	rk = test_create_consumer(NULL, NULL, NULL, NULL);
	rkt = test_create_topic_object(rk, topic, "auto.offset.reset", reset,
				       NULL);

	test_consumer_start(reset, rkt, partition, initial_offset);
	while (1) {
		rd_kafka_message_t *rkm;

		rkm = rd_kafka_consume(rkt, partition, tmout_multip(1000*10));
		if (!rkm)
			TEST_FAIL("%s: no message for 10s: "
				  "%d/%d messages, %d/%d EOFs, %d/%d errors\n",
				  reset, msgcnt, exp_msgcnt,
				  eofcnt, exp_eofcnt,
				  errcnt, exp_errcnt);

		if (rkm->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
			TEST_SAY("%s: received EOF at offset %"PRId64"\n",
				 reset, rkm->offset);
			eofcnt++;
		} else if (rkm->err) {
			TEST_SAY("%s: consume error at offset %"PRId64": %s\n",
				 reset, rkm->offset,
				 rd_kafka_message_errstr(rkm));
			errcnt++;
		} else {
			msgcnt++;
		}

		rd_kafka_message_destroy(rkm);

		if (eofcnt == exp_eofcnt &&
		    errcnt == exp_errcnt &&
		    msgcnt == exp_msgcnt)
			break;
		else if (eofcnt > exp_eofcnt ||
			 errcnt > exp_errcnt ||
			 msgcnt > exp_msgcnt)
			TEST_FAIL("%s: unexpected: "
				  "%d/%d messages, %d/%d EOFs, %d/%d errors\n",
				  reset,
				  msgcnt, exp_msgcnt,
				  eofcnt, exp_eofcnt,
				  errcnt, exp_errcnt);
			 
	}

	TEST_SAY("%s: Done: "
		 "%d/%d messages, %d/%d EOFs, %d/%d errors\n",
		 reset,
		 msgcnt, exp_msgcnt,
		 eofcnt, exp_eofcnt,
		 errcnt, exp_errcnt);

	test_consumer_stop(reset, rkt, partition);

	rd_kafka_topic_destroy(rkt);
	rd_kafka_destroy(rk);
}

int main_0034_offset_reset (int argc, char **argv) {
	const char *topic = test_mk_topic_name(__FUNCTION__, 1);
	const int partition = 0;
	const int msgcnt = 100;

	/* Produce messages */
	test_produce_msgs_easy(topic, 0, partition, msgcnt);

	/* auto.offset.reset=latest: Consume messages from invalid offset:
	 * Should return EOF. */
	do_test_reset(topic, partition, "latest", msgcnt+5, 1, 0, 0);
	
	/* auto.offset.reset=earliest: Consume messages from invalid offset:
	 * Should return messages from beginning. */
	do_test_reset(topic, partition, "earliest", msgcnt+5, 1, msgcnt, 0);

	/* auto.offset.reset=error: Consume messages from invalid offset:
	 * Should return error. */
	do_test_reset(topic, partition, "error", msgcnt+5, 0, 0, 1);

	return 0;
}
