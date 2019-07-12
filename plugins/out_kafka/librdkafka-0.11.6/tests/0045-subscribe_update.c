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
 * Verify that subscription is updated on metadata changes:
 *  - topic additions
 *  - topic deletions
 *  - partition count changes
 */



/**
 * Wait for REBALANCE ASSIGN event and perform assignment
 *
 * Va-args are \p topic_cnt tuples of the expected assignment:
 *   { const char *topic, int partition_cnt }
 */
static void await_assignment (const char *pfx, rd_kafka_t *rk,
			      rd_kafka_queue_t *queue,
			      int topic_cnt, ...) {
	rd_kafka_event_t *rkev;
	rd_kafka_topic_partition_list_t *tps;
	int i;
	va_list ap;
	int fails = 0;
	int exp_part_cnt = 0;

	TEST_SAY("%s: waiting for assignment\n", pfx);
	rkev = test_wait_event(queue, RD_KAFKA_EVENT_REBALANCE, 30000);
	if (!rkev)
		TEST_FAIL("timed out waiting for assignment");
	TEST_ASSERT(rd_kafka_event_error(rkev) ==
		    RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
		    "expected ASSIGN, got %s",
		    rd_kafka_err2str(rd_kafka_event_error(rkev)));
	tps = rd_kafka_event_topic_partition_list(rkev);

	TEST_SAY("%s: assignment:\n", pfx);
	test_print_partition_list(tps);

	va_start(ap, topic_cnt);
	for (i = 0 ; i < topic_cnt ; i++) {
		const char *topic = va_arg(ap, const char *);
		int partition_cnt = va_arg(ap, int);
		int p;
		TEST_SAY("%s: expecting %s with %d partitions\n",
			 pfx, topic, partition_cnt);
		for (p = 0 ; p < partition_cnt ; p++) {
			if (!rd_kafka_topic_partition_list_find(tps, topic, p)) {
				TEST_FAIL_LATER("%s: expected partition %s [%d] "
						"not found in assginment",
						pfx, topic, p);
				fails++;
			}
		}
		exp_part_cnt += partition_cnt;
	}
	va_end(ap);

	TEST_ASSERT(exp_part_cnt == tps->cnt,
		    "expected assignment of %d partitions, got %d",
		    exp_part_cnt, tps->cnt);

	if (fails > 0)
		TEST_FAIL("%s: assignment mismatch: see above", pfx);

	rd_kafka_assign(rk, tps);
	rd_kafka_event_destroy(rkev);
}


/**
 * Wait for REBALANCE REVOKE event and perform unassignment.
 */
static void await_revoke (const char *pfx, rd_kafka_t *rk,
			  rd_kafka_queue_t *queue) {
	rd_kafka_event_t *rkev;

	TEST_SAY("%s: waiting for revoke\n", pfx);
	rkev = test_wait_event(queue, RD_KAFKA_EVENT_REBALANCE, 30000);
	if (!rkev)
		TEST_FAIL("timed out waiting for revoke");
	TEST_ASSERT(rd_kafka_event_error(rkev) ==
		    RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS,
		    "expected REVOKE, got %s",
		    rd_kafka_err2str(rd_kafka_event_error(rkev)));
	rd_kafka_assign(rk, NULL);
	rd_kafka_event_destroy(rkev);
}

/**
 * Wait \p timeout_ms to make sure no rebalance was triggered.
 */
static void await_no_rebalance (const char *pfx, rd_kafka_t *rk,
				rd_kafka_queue_t *queue, int timeout_ms) {
	rd_kafka_event_t *rkev;

	TEST_SAY("%s: waiting for %d ms to not see rebalance\n",
		 pfx, timeout_ms);
	rkev = test_wait_event(queue, RD_KAFKA_EVENT_REBALANCE, timeout_ms);
	if (!rkev)
		return;
	TEST_ASSERT(rkev, "did not expect %s: %s",
		    rd_kafka_event_name(rkev),
		    rd_kafka_err2str(rd_kafka_event_error(rkev)));
	rd_kafka_event_destroy(rkev);

}

static void do_test_non_exist_and_partchange (void) {
	char *topic_a = rd_strdup(test_mk_topic_name("topic_a", 1));
	rd_kafka_t *rk;
	rd_kafka_conf_t *conf;
	rd_kafka_queue_t *queue;

	/**
	 * Test #1:
	 * - Subscribe to non-existing topic.
	 * - Verify empty assignment
	 * - Create topic
	 * - Verify new assignment containing topic
	 */
	TEST_SAY("#1 & #2 testing\n");
	test_conf_init(&conf, NULL, 60);

	/* Decrease metadata interval to speed up topic change discovery. */
	test_conf_set(conf, "topic.metadata.refresh.interval.ms", "5000");

	rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_REBALANCE);
	rk = test_create_consumer(test_str_id_generate_tmp(),
				  NULL, conf, NULL);
	queue = rd_kafka_queue_get_consumer(rk);

	TEST_SAY("#1: Subscribing to %s\n", topic_a);
	test_consumer_subscribe(rk, topic_a);

	/* Should not see a rebalance since no topics are matched. */
	await_no_rebalance("#1: empty", rk, queue, 10000);

	TEST_SAY("#1: creating topic %s\n", topic_a);
	test_create_topic(topic_a, 2, 1);

	await_assignment("#1: proper", rk, queue, 1,
			 topic_a, 2);


	/**
	 * Test #2 (continue with #1 consumer)
	 * - Increase the partition count
	 * - Verify updated assignment
	 */
	test_kafka_topics("--alter --topic %s --partitions 4",
			  topic_a);
	await_revoke("#2", rk, queue);

	await_assignment("#2: more partitions", rk, queue, 1,
			 topic_a, 4);

	test_consumer_close(rk);
	rd_kafka_queue_destroy(queue);
	rd_kafka_destroy(rk);

	rd_free(topic_a);
}



static void do_test_regex (void) {
	char *base_topic = rd_strdup(test_mk_topic_name("topic", 1));
	char *topic_b = rd_strdup(tsprintf("%s_b", base_topic));
	char *topic_c = rd_strdup(tsprintf("%s_c", base_topic));
	char *topic_d = rd_strdup(tsprintf("%s_d", base_topic));
	char *topic_e = rd_strdup(tsprintf("%s_e", base_topic));
	rd_kafka_t *rk;
	rd_kafka_conf_t *conf;
	rd_kafka_queue_t *queue;

	/**
	 * Regex test:
	 * - Create topic b
	 * - Subscribe to b & d & e
	 * - Verify b assignment
	 * - Create topic c
	 * - Verify no rebalance
	 * - Create topic d
	 * - Verify b & d assignment
	 */
	TEST_SAY("Regex testing\n");
	test_conf_init(&conf, NULL, 60);

	/* Decrease metadata interval to speed up topic change discovery. */
	test_conf_set(conf, "topic.metadata.refresh.interval.ms", "5000");

	rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_REBALANCE);
	rk = test_create_consumer(test_str_id_generate_tmp(),
				  NULL, conf, NULL);
	queue = rd_kafka_queue_get_consumer(rk);

	TEST_SAY("Regex: creating topic %s (subscribed)\n", topic_b);
	test_create_topic(topic_b, 2, 1);
	rd_sleep(1); // FIXME: do check&wait loop instead

	TEST_SAY("Regex: Subscribing to %s & %s & %s\n",
		 topic_b, topic_d, topic_e);
	test_consumer_subscribe(rk, tsprintf("^%s_[bde]$", base_topic));

	await_assignment("Regex: just one topic exists", rk, queue, 1,
			 topic_b, 2);

	TEST_SAY("Regex: creating topic %s (not subscribed)\n", topic_c);
	test_create_topic(topic_c, 4, 1);

	/* Should not see a rebalance since no topics are matched. */
	await_no_rebalance("Regex: empty", rk, queue, 10000);

	TEST_SAY("Regex: creating topic %s (subscribed)\n", topic_d);
	test_create_topic(topic_d, 1, 1);

	await_revoke("Regex: rebalance after topic creation", rk, queue);

	await_assignment("Regex: two topics exist", rk, queue, 2,
			 topic_b, 2,
			 topic_d, 1);

	test_consumer_close(rk);
	rd_kafka_queue_destroy(queue);
	rd_kafka_destroy(rk);

	rd_free(base_topic);
	rd_free(topic_b);
	rd_free(topic_c);
	rd_free(topic_d);
	rd_free(topic_e);
}


/* @remark This test will fail if auto topic creation is enabled on the broker
 * since the client will issue a topic-creating metadata request to find
 * a new leader when the topic is removed.
 *
 * To run with trivup, do:
 * ./interactive_broker_version.py .. -conf '{"auto_create_topics":"false"}' ..
 * TESTS=0045 ./run-test.sh -k ./merged
 */
static void do_test_topic_remove (void) {
	char *topic_f = rd_strdup(test_mk_topic_name("topic_f", 1));
	char *topic_g = rd_strdup(test_mk_topic_name("topic_g", 1));
	int parts_f = 5;
	int parts_g = 9;
	rd_kafka_t *rk;
	rd_kafka_conf_t *conf;
	rd_kafka_queue_t *queue;
	rd_kafka_topic_partition_list_t *topics;
	rd_kafka_resp_err_t err;

	/**
	 * Topic removal test:
	 * - Create topic f & g
	 * - Subscribe to f & g
	 * - Verify f & g assignment
	 * - Remove topic f
	 * - Verify g assignment
	 * - Remove topic g
	 * - Verify empty assignment
	 */
	TEST_SAY("Topic removal testing\n");
	test_conf_init(&conf, NULL, 60);

	/* Decrease metadata interval to speed up topic change discovery. */
	test_conf_set(conf, "topic.metadata.refresh.interval.ms", "5000");

	rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_REBALANCE);
	rk = test_create_consumer(test_str_id_generate_tmp(),
				  NULL, conf, NULL);
	queue = rd_kafka_queue_get_consumer(rk);

	TEST_SAY("Topic removal: creating topic %s (subscribed)\n", topic_f);
	test_create_topic(topic_f, parts_f, 1);

	TEST_SAY("Topic removal: creating topic %s (subscribed)\n", topic_g);
	test_create_topic(topic_g, parts_g, 1);

	rd_sleep(1); // FIXME: do check&wait loop instead

	TEST_SAY("Topic removal: Subscribing to %s & %s\n", topic_f, topic_g);
	topics = rd_kafka_topic_partition_list_new(2);
	rd_kafka_topic_partition_list_add(topics, topic_f, RD_KAFKA_PARTITION_UA);
	rd_kafka_topic_partition_list_add(topics, topic_g, RD_KAFKA_PARTITION_UA);
	err = rd_kafka_subscribe(rk, topics);
	TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
		    "%s", rd_kafka_err2str(err));
	rd_kafka_topic_partition_list_destroy(topics);

	await_assignment("Topic removal: both topics exist", rk, queue, 2,
			 topic_f, parts_f,
			 topic_g, parts_g);

	TEST_SAY("Topic removal: removing %s\n", topic_f);
	test_kafka_topics("--delete --topic %s", topic_f);

	await_revoke("Topic removal: rebalance after topic removal", rk, queue);

	await_assignment("Topic removal: one topic exists", rk, queue, 1,
			 topic_g, parts_g);
	
	TEST_SAY("Topic removal: removing %s\n", topic_g);
	test_kafka_topics("--delete --topic %s", topic_g);

	await_revoke("Topic removal: rebalance after 2nd topic removal",
		     rk, queue);

	/* Should not see another rebalance since all topics now removed */
	await_no_rebalance("Topic removal: empty", rk, queue, 10000);

	test_consumer_close(rk);
	rd_kafka_queue_destroy(queue);
	rd_kafka_destroy(rk);

	rd_free(topic_f);
	rd_free(topic_g);
}


int main_0045_subscribe_update (int argc, char **argv) {

        if (!test_can_create_topics(1))
                return 0;

        do_test_regex();

        return 0;
}

int main_0045_subscribe_update_non_exist_and_partchange (int argc, char **argv){
        if (test_check_auto_create_topic()) {
                TEST_SKIP("do_test_non_exist_and_partchange(): "
                          "topic auto-creation is enabled\n");
                return 0;
        }

        do_test_non_exist_and_partchange();

        return 0;
}

int main_0045_subscribe_update_topic_remove (int argc, char **argv) {

	if (!test_can_create_topics(1))
		return 0;

	do_test_topic_remove();

        return 0;
}
