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

static int prod_msg_remains = 0;
static int fails = 0;

/**
 * Delivery reported callback.
 * Called for each message once to signal its delivery status.
 */
static void dr_cb (rd_kafka_t *rk, void *payload, size_t len,
		   rd_kafka_resp_err_t err, void *opaque, void *msg_opaque) {

	if (err != RD_KAFKA_RESP_ERR_NO_ERROR)
		TEST_FAIL("Message delivery failed: %s\n",
			  rd_kafka_err2str(err));

	if (prod_msg_remains == 0)
		TEST_FAIL("Too many messages delivered (prod_msg_remains %i)",
			  prod_msg_remains);

	prod_msg_remains--;
}


/**
 * Produces 'msgcnt' messages split over 'partition_cnt' partitions.
 */
static void produce_messages (uint64_t testid, const char *topic,
                              int partition_cnt, int msg_base, int msgcnt) {
	int r;
	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *topic_conf;
	char errstr[512];
	int i;
	int32_t partition;
	int msgid = msg_base;

	test_conf_init(&conf, &topic_conf, 20);

	rd_kafka_conf_set_dr_cb(conf, dr_cb);

        /* Make sure all replicas are in-sync after producing
         * so that consume test wont fail. */
        rd_kafka_topic_conf_set(topic_conf, "request.required.acks", "-1",
                                errstr, sizeof(errstr));

	/* Create kafka instance */
	rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

	rkt = rd_kafka_topic_new(rk, topic, topic_conf);
	if (!rkt)
		TEST_FAIL("Failed to create topic: %s\n",
                          rd_kafka_err2str(rd_kafka_last_error()));

        /* Produce messages */
	prod_msg_remains = msgcnt;
	for (partition = 0 ; partition < partition_cnt ; partition++) {
		int batch_cnt = msgcnt / partition_cnt;

		for (i = 0 ; i < batch_cnt ; i++) {
                        char key[128];
                        char buf[128];
			rd_snprintf(key, sizeof(key),
				 "testid=%"PRIu64", partition=%i, msg=%i",
				 testid, (int)partition, msgid);
                        rd_snprintf(buf, sizeof(buf),
                                 "data: testid=%"PRIu64", partition=%i, msg=%i",
				 testid, (int)partition, msgid);

                        r = rd_kafka_produce(rkt, partition,
                                             RD_KAFKA_MSG_F_COPY,
                                             buf, strlen(buf),
                                             key, strlen(key),
                                             NULL);
                        if (r == -1)
                                TEST_FAIL("Failed to produce message %i "
                                          "to partition %i: %s",
                                          msgid, (int)partition,
                                          rd_kafka_err2str(rd_kafka_last_error()));
			msgid++;
		}
        }


	/* Wait for messages to be delivered */
	while (rd_kafka_outq_len(rk) > 0)
		rd_kafka_poll(rk, 100);

	if (fails)
		TEST_FAIL("%i failures, see previous errors", fails);

	if (prod_msg_remains != 0)
		TEST_FAIL("Still waiting for %i messages to be produced",
			  prod_msg_remains);

	/* Destroy topic */
	rd_kafka_topic_destroy(rkt);

	/* Destroy rdkafka instance */
	TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
	rd_kafka_destroy(rk);
}



static int *cons_msgs;
static int  cons_msgs_size;
static int  cons_msgs_cnt;
static int  cons_msg_next;
static int  cons_msg_stop = -1;
static int64_t cons_last_offset = -1;  /* last offset received */

static void verify_consumed_msg_reset (int msgcnt) {
	if (cons_msgs) {
		free(cons_msgs);
		cons_msgs = NULL;
	}

	if (msgcnt) {
		int i;

		cons_msgs = malloc(sizeof(*cons_msgs) * msgcnt);
		for (i = 0 ; i < msgcnt ; i++)
			cons_msgs[i] = -1;
	}

	cons_msgs_size = msgcnt;
	cons_msgs_cnt = 0;
        cons_msg_next = 0;
        cons_msg_stop = -1;
        cons_last_offset = -1;

        TEST_SAY("Reset consumed_msg stats, making room for %d new messages\n",
                 msgcnt);
}


static int int_cmp (const void *_a, const void *_b) {
	int a = *(int *)_a;
	int b = *(int *)_b;
        /* Sort -1 (non-received msgs) at the end */
	return (a == -1 ? 100000000 : a) - (b == -1 ? 10000000 : b);
}

static void verify_consumed_msg_check0 (const char *func, int line,
                                        const char *desc,
                                        int expected_cnt) {
	int i;
	int fails = 0;
        int not_recvd = 0;

        TEST_SAY("%s: received %d/%d/%d messages\n",
                 desc, cons_msgs_cnt, expected_cnt, cons_msgs_size);
        if (expected_cnt > cons_msgs_size)
                TEST_FAIL("expected_cnt %d > cons_msgs_size %d\n",
                          expected_cnt, cons_msgs_size);

	if (cons_msgs_cnt < expected_cnt) {
		TEST_SAY("%s: Missing %i messages in consumer\n",
			 desc,expected_cnt - cons_msgs_cnt);
		fails++;
	}

	qsort(cons_msgs, cons_msgs_size, sizeof(*cons_msgs), int_cmp);

	for (i = 0 ; i < expected_cnt ; i++) {
		if (cons_msgs[i] != i) {
                        if (cons_msgs[i] == -1) {
                                not_recvd++;
                                TEST_SAY("%s: msg %d/%d not received\n",
                                         desc, i, expected_cnt);
                        } else
                                TEST_SAY("%s: Consumed message #%i is wrong, "
                                         "expected #%i\n",
                                         desc, cons_msgs[i], i);
			fails++;
		}
	}

        if (not_recvd)
                TEST_SAY("%s: %d messages not received at all\n",
                         desc, not_recvd);

	if (fails)
		TEST_FAIL("%s: See above error(s)", desc);
        else
                TEST_SAY("%s: message range check: %d/%d messages consumed: "
                         "succeeded\n", desc, cons_msgs_cnt, expected_cnt);

}


#define verify_consumed_msg_check(desc,expected_cnt)                        \
	verify_consumed_msg_check0(__FUNCTION__,__LINE__, desc, expected_cnt)



static void verify_consumed_msg0 (const char *func, int line,
				  uint64_t testid, int32_t partition,
				  int msgnum,
				  rd_kafka_message_t *rkmessage) {
	uint64_t in_testid;
	int in_part;
	int in_msgnum;
	char buf[128];

	if (rkmessage->key_len +1 >= sizeof(buf))
		TEST_FAIL("Incoming message key too large (%i): "
			  "not sourced by this test",
			  (int)rkmessage->key_len);

	rd_snprintf(buf, sizeof(buf), "%.*s",
		 (int)rkmessage->key_len, (char *)rkmessage->key);

	if (sscanf(buf, "testid=%"SCNu64", partition=%i, msg=%i",
		   &in_testid, &in_part, &in_msgnum) != 3)
		TEST_FAIL("Incorrect key format: %s", buf);

        if (test_level > 2) {
		TEST_SAY("%s:%i: Our testid %"PRIu64", part %i (%i), "
			 "msg %i/%i, key's: \"%s\"\n",
			 func, line,
			 testid, (int)partition, (int)rkmessage->partition,
			 msgnum, cons_msgs_size, buf);
	}

	if (testid != in_testid ||
	    (partition != -1 && partition != in_part) ||
	    (msgnum != -1 && msgnum != in_msgnum) ||
	    (in_msgnum < 0 || in_msgnum > cons_msgs_size))
		goto fail_match;

	if (cons_msgs_cnt == cons_msgs_size) {
		TEST_SAY("Too many messages in cons_msgs (%i) while reading "
			 "message key \"%s\"\n",
			 cons_msgs_cnt, buf);
		verify_consumed_msg_check("?", cons_msgs_size);
		TEST_FAIL("See above error(s)");
	}

	cons_msgs[cons_msgs_cnt++] = in_msgnum;
        cons_last_offset = rkmessage->offset;

	return;

 fail_match:
	TEST_FAIL("%s:%i: Our testid %"PRIu64", part %i, msg %i/%i did "
		  "not match message's key: \"%s\"\n",
		  func, line,
		  testid, (int)partition, msgnum, cons_msgs_size, buf);
}

#define verify_consumed_msg(testid,part,msgnum,rkmessage) \
	verify_consumed_msg0(__FUNCTION__,__LINE__,testid,part,msgnum,rkmessage)


static void consume_cb (rd_kafka_message_t *rkmessage, void *opaque) {
        int64_t testid = *(int64_t *)opaque;

	if (test_level > 2)
		TEST_SAY("Consumed message #%d? at offset %"PRId64": %s\n",
			 cons_msg_next, rkmessage->offset,
			 rd_kafka_err2str(rkmessage->err));

        if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
                TEST_SAY("EOF at offset %"PRId64"\n", rkmessage->offset);
                return;
        }

        if (rkmessage->err)
                TEST_FAIL("Consume message from partition %i "
                          "has error: %s",
                          (int)rkmessage->partition,
                          rd_kafka_err2str(rkmessage->err));

        verify_consumed_msg(testid, rkmessage->partition,
                            cons_msg_next, rkmessage);

        if (cons_msg_next == cons_msg_stop) {
                rd_kafka_yield(NULL/*FIXME*/);
        }

        cons_msg_next++;
}

static void consume_messages_callback_multi (const char *desc,
                                             uint64_t testid, const char *topic,
                                             int32_t partition,
                                             const char *offset_store_method,
                                             int msg_base,
                                             int msg_cnt,
                                             int64_t initial_offset,
                                             int iterations) {
	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *topic_conf;
	int i;

        TEST_SAY("%s: Consume messages %d+%d from %s [%"PRId32"] "
                 "from offset %"PRId64" in %d iterations\n",
                 desc, msg_base, msg_cnt, topic, partition,
                 initial_offset, iterations);

	test_conf_init(&conf, &topic_conf, 20);

        test_topic_conf_set(topic_conf, "offset.store.method",
                            offset_store_method);

        if (!strcmp(offset_store_method, "broker")) {
                /* Broker based offset storage requires a group.id */
                test_conf_set(conf, "group.id", topic);
        }

	/* Create kafka instance */
	rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        rd_kafka_topic_conf_set(topic_conf, "auto.offset.reset", "smallest",
                                NULL, 0);

	rkt = rd_kafka_topic_new(rk, topic, topic_conf);
	if (!rkt)
		TEST_FAIL("%s: Failed to create topic: %s\n",
                          desc, rd_kafka_err2str(rd_kafka_last_error()));

	cons_msg_stop = cons_msg_next + msg_cnt - 1;

        /* Consume the same batch of messages multiple times to
         * make sure back-to-back start&stops work. */
        for (i = 0 ; i < iterations ; i++) {
                int cnta;
                test_timing_t t_stop;

                TEST_SAY("%s: Iteration #%i: Consuming from "
                         "partition %i at offset %"PRId64", "
                         "msgs range %d..%d\n",
                         desc, i, partition, initial_offset,
                         cons_msg_next, cons_msg_stop);

                /* Consume messages */
                if (rd_kafka_consume_start(rkt, partition, initial_offset) == -1)
                        TEST_FAIL("%s: consume_start(%i) failed: %s",
                                  desc, (int)partition,
                                  rd_kafka_err2str(rd_kafka_last_error()));


                /* Stop consuming messages when this number of messages
                 * is reached. */
                cnta = cons_msg_next;
                do {
                        rd_kafka_consume_callback(rkt, partition, 1000,
                                                  consume_cb, &testid);
                } while (cons_msg_next < cons_msg_stop);

                TEST_SAY("%s: Iteration #%i: consumed %i messages\n",
                         desc, i, cons_msg_next - cnta);

                TIMING_START(&t_stop, "rd_kafka_consume_stop()");
                rd_kafka_consume_stop(rkt, partition);
                TIMING_STOP(&t_stop);

                /* Advance next offset so we dont reconsume
                 * messages on the next run. */
                if (initial_offset != RD_KAFKA_OFFSET_STORED) {
                        initial_offset = cons_last_offset+1;
			cons_msg_stop = cons_msg_next + msg_cnt - 1;
		}
        }

	/* Destroy topic */
	rd_kafka_topic_destroy(rkt);

	/* Destroy rdkafka instance */
	TEST_SAY("%s: Destroying kafka instance %s\n", desc, rd_kafka_name(rk));
	rd_kafka_destroy(rk);
}



static void test_produce_consume (const char *offset_store_method) {
	int msgcnt = 100;
        int partition_cnt = 1;
	int i;
	uint64_t testid;
	int msg_base = 0;
        const char *topic;

	/* Generate a testid so we can differentiate messages
	 * from other tests */
	testid = test_id_generate();

        /* Read test.conf to configure topic name */
        test_conf_init(NULL, NULL, 20);
        topic = test_mk_topic_name("0014", 1/*random*/);

	TEST_SAY("Topic %s, testid %"PRIu64", offset.store.method=%s\n",
                 topic, testid, offset_store_method);

	/* Produce messages */
	produce_messages(testid, topic, partition_cnt, msg_base, msgcnt);

        /* 100% of messages */
        verify_consumed_msg_reset(msgcnt);

	/* Consume 50% of messages with callbacks: stored offsets with no prior
         * offset stored. */
	for (i = 0 ; i < partition_cnt ; i++)
		consume_messages_callback_multi("STORED.1/2", testid, topic, i,
                                                offset_store_method,
                                                msg_base,
                                                (msgcnt / partition_cnt) / 2,
                                                RD_KAFKA_OFFSET_STORED,
                                                1);
        verify_consumed_msg_check("STORED.1/2", msgcnt / 2);

        /* Consume the rest using the now stored offset */
        for (i = 0 ; i < partition_cnt ; i++)
		consume_messages_callback_multi("STORED.2/2", testid, topic, i,
                                                offset_store_method,
                                                msg_base,
                                                (msgcnt / partition_cnt) / 2,
                                                RD_KAFKA_OFFSET_STORED,
                                                1);
        verify_consumed_msg_check("STORED.2/2", msgcnt);


	/* Consume messages with callbacks: logical offsets */
	verify_consumed_msg_reset(msgcnt);
	for (i = 0 ; i < partition_cnt ; i++) {
                int p_msg_cnt = msgcnt / partition_cnt;
                int64_t initial_offset = RD_KAFKA_OFFSET_TAIL(p_msg_cnt);
                const int iterations = 4;
		consume_messages_callback_multi("TAIL+", testid, topic, i,
                                                offset_store_method,
                                                /* start here (msgid) */
                                                msg_base,
                                                /* consume this many messages
                                                 * per iteration. */
                                                p_msg_cnt / iterations,
                                                /* start here (offset) */
                                                initial_offset,
                                                iterations);
        }

        verify_consumed_msg_check("TAIL+", msgcnt);

        verify_consumed_msg_reset(0);

	return;
}




int main_0014_reconsume_191 (int argc, char **argv) {
	if (test_broker_version >= TEST_BRKVER(0,8,2,0))
		test_produce_consume("broker");
        test_produce_consume("file");
	return 0;
}
