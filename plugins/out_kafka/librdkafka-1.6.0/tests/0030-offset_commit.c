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
 * Consumer: various offset commit constellations, matrix:
 *   enable.auto.commit, enable.auto.offset.store, async
 */

static const char *topic;
static const int msgcnt = 100;
static const int partition = 0;
static uint64_t testid;

static int64_t expected_offset = 0;
static int64_t committed_offset = -1;


static void offset_commit_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
			      rd_kafka_topic_partition_list_t *offsets,
			      void *opaque) {
	rd_kafka_topic_partition_t *rktpar;

	TEST_SAYL(3, "Offset committed: %s:\n", rd_kafka_err2str(err));
	if (err == RD_KAFKA_RESP_ERR__NO_OFFSET)
		return;

	test_print_partition_list(offsets);
	if (err)
		TEST_FAIL("Offset commit failed: %s", rd_kafka_err2str(err));
	if (offsets->cnt == 0)
		TEST_FAIL("Expected at least one partition in offset_commit_cb");

	/* Find correct partition */
	if (!(rktpar = rd_kafka_topic_partition_list_find(offsets,
							  topic, partition)))
		return;

	if (rktpar->err)
		TEST_FAIL("Offset commit failed for partitioń : %s",
			  rd_kafka_err2str(rktpar->err));

	if (rktpar->offset > expected_offset)
		TEST_FAIL("Offset committed %"PRId64
			  " > expected offset %"PRId64,
			  rktpar->offset, expected_offset);

        if (rktpar->offset < committed_offset)
                TEST_FAIL("Old offset %"PRId64" (re)committed: "
                          "should be above committed_offset %"PRId64,
                          rktpar->offset, committed_offset);
        else if (rktpar->offset == committed_offset)
                TEST_SAYL(1, "Current offset re-committed: %"PRId64"\n",
                          rktpar->offset);
        else
                committed_offset = rktpar->offset;

	if (rktpar->offset < expected_offset) {
		TEST_SAYL(3, "Offset committed %"PRId64
			  " < expected offset %"PRId64"\n",
			  rktpar->offset, expected_offset);
		return;
	}

	TEST_SAYL(3, "Expected offset committed: %"PRId64"\n", rktpar->offset);
}


static void do_offset_test (const char *what, int auto_commit, int auto_store,
			    int async) {
	test_timing_t t_all;
	char groupid[64];
	rd_kafka_t *rk;
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *tconf;
	int cnt = 0;
	const int extra_cnt = 5;
	rd_kafka_resp_err_t err;
	rd_kafka_topic_partition_list_t *parts;
	rd_kafka_topic_partition_t *rktpar;
	int64_t next_offset = -1;

	test_conf_init(&conf, &tconf, 30);
        test_conf_set(conf, "session.timeout.ms", "6000");
	test_conf_set(conf, "enable.auto.commit", auto_commit ? "true":"false");
	test_conf_set(conf, "enable.auto.offset.store", auto_store ?"true":"false");
	test_conf_set(conf, "auto.commit.interval.ms", "500");
	rd_kafka_conf_set_offset_commit_cb(conf, offset_commit_cb);
	test_topic_conf_set(tconf, "auto.offset.reset", "smallest");
	test_str_id_generate(groupid, sizeof(groupid));
	test_conf_set(conf, "group.id", groupid);
	rd_kafka_conf_set_default_topic_conf(conf, tconf);

	TEST_SAY(_C_MAG "[ do_offset_test: %s with group.id %s ]\n",
		 what, groupid);

	TIMING_START(&t_all, "%s", what);

	expected_offset  = 0;
	committed_offset = -1;

	/* MO:
	 *  - Create consumer.
	 *  - Start consuming from beginning
	 *  - Perform store & commits according to settings
	 *  - Stop storing&committing when half of the messages are consumed,
	 *  - but consume 5 more to check against.
	 *  - Query position.
	 *  - Destroy consumer.
	 *  - Create new consumer with same group.id using stored offsets
	 *  - Should consume the expected message.
	 */

	/* Create kafka instance */
	rk = test_create_handle(RD_KAFKA_CONSUMER, rd_kafka_conf_dup(conf));

	rd_kafka_poll_set_consumer(rk);

	test_consumer_subscribe(rk, topic);

	while (cnt - extra_cnt < msgcnt / 2) {
		rd_kafka_message_t *rkm;

		rkm = rd_kafka_consumer_poll(rk, 10*1000);
		if (!rkm)
			continue;

		if (rkm->err == RD_KAFKA_RESP_ERR__TIMED_OUT)
			TEST_FAIL("%s: Timed out waiting for message %d", what,cnt);
                else if (rkm->err)
			TEST_FAIL("%s: Consumer error: %s",
				  what, rd_kafka_message_errstr(rkm));

		/* Offset of next message. */
		next_offset = rkm->offset + 1;

		if (cnt < msgcnt / 2) {
			if (!auto_store) {
				err = rd_kafka_offset_store(rkm->rkt,rkm->partition,
							    rkm->offset);
				if (err)
					TEST_FAIL("%s: offset_store failed: %s\n",
						  what, rd_kafka_err2str(err));
			}
			expected_offset = rkm->offset+1;
			if (!auto_commit) {
                                test_timing_t t_commit;
                                TIMING_START(&t_commit,
                                             "%s @ %"PRId64,
                                             async?
                                             "commit.async":
                                             "commit.sync",
                                             rkm->offset+1);
				err = rd_kafka_commit_message(rk, rkm, async);
				TIMING_STOP(&t_commit);
				if (err)
					TEST_FAIL("%s: commit failed: %s\n",
						  what, rd_kafka_err2str(err));
			}

		} else if (auto_store && auto_commit)
			expected_offset = rkm->offset+1;

		rd_kafka_message_destroy(rkm);
		cnt++;
	}

	TEST_SAY("%s: done consuming after %d messages, at offset %"PRId64
                 ", next_offset %"PRId64"\n",
		 what, cnt, expected_offset, next_offset);

	if ((err = rd_kafka_assignment(rk, &parts)))
		TEST_FAIL("%s: failed to get assignment(): %s\n",
			  what, rd_kafka_err2str(err));

	/* Verify position */
	if ((err = rd_kafka_position(rk, parts)))
		TEST_FAIL("%s: failed to get position(): %s\n",
			  what, rd_kafka_err2str(err));
	if (!(rktpar = rd_kafka_topic_partition_list_find(parts,
							  topic, partition)))
		TEST_FAIL("%s: position(): topic lost\n", what);
	if (rktpar->offset != next_offset)
		TEST_FAIL("%s: Expected position() offset %"PRId64", got %"PRId64,
			  what, next_offset, rktpar->offset);
	TEST_SAY("%s: Position is at %"PRId64", good!\n",
		 what, rktpar->offset);

	/* Pause messages while waiting so we can serve callbacks
	 * without having more messages received. */
	if ((err = rd_kafka_pause_partitions(rk, parts)))
		TEST_FAIL("%s: failed to pause partitions: %s\n",
			  what, rd_kafka_err2str(err));
	rd_kafka_topic_partition_list_destroy(parts);

	/* Fire off any enqueued offset_commit_cb */
	test_consumer_poll_no_msgs(what, rk, testid, 0);

	TEST_SAY("%s: committed_offset %"PRId64", expected_offset %"PRId64"\n",
		 what, committed_offset, expected_offset);

	if (!auto_commit && !async) {
		/* Sync commits should be up to date at this point. */
		if (committed_offset != expected_offset)
			TEST_FAIL("%s: Sync commit: committed offset %"PRId64
				  " should be same as expected offset "
				  "%"PRId64,
				  what, committed_offset, expected_offset);
	} else {

		/* Wait for offset commits to catch up */
		while (committed_offset < expected_offset) {
			TEST_SAYL(2, "%s: Wait for committed offset %"PRId64
				  " to reach expected offset %"PRId64"\n",
				  what, committed_offset, expected_offset);
			test_consumer_poll_no_msgs(what, rk, testid, 1000);
		}

	}

	TEST_SAY("%s: phase 1 complete, %d messages consumed, "
		 "next expected offset is %"PRId64"\n",
		 what, cnt, expected_offset);

        /* Issue #827: cause committed() to return prematurely by specifying
         *             low timeout. The bug (use after free) will only
         *             be catched by valgrind.
         *
         * rusage: this triggers a bunch of protocol requests which
         *         increase .ucpu, .scpu, .ctxsw.
         */
        do {
                parts = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(parts, topic, partition);
                err = rd_kafka_committed(rk, parts, 1);
                rd_kafka_topic_partition_list_destroy(parts);
                if (err)
                        TEST_SAY("Issue #827: committed() returned %s\n",
                                 rd_kafka_err2str(err));
        } while (err != RD_KAFKA_RESP_ERR__TIMED_OUT);

	/* Query position */
	parts = rd_kafka_topic_partition_list_new(1);
	rd_kafka_topic_partition_list_add(parts, topic, partition);

	err = rd_kafka_committed(rk, parts, tmout_multip(5*1000));
	if (err)
		TEST_FAIL("%s: committed() failed: %s", what, rd_kafka_err2str(err));
	if (!(rktpar = rd_kafka_topic_partition_list_find(parts,
							  topic, partition)))
		TEST_FAIL("%s: committed(): topic lost\n", what);
	if (rktpar->offset != expected_offset)
		TEST_FAIL("%s: Expected committed() offset %"PRId64", got %"PRId64,
			  what, expected_offset, rktpar->offset);
	TEST_SAY("%s: Committed offset is at %"PRId64", good!\n",
		 what, rktpar->offset);

	rd_kafka_topic_partition_list_destroy(parts);
	test_consumer_close(rk);
	rd_kafka_destroy(rk);



	/* Fire up a new consumer and continue from where we left off. */
	TEST_SAY("%s: phase 2: starting new consumer to resume consumption\n",what);
	rk = test_create_handle(RD_KAFKA_CONSUMER, conf);
	rd_kafka_poll_set_consumer(rk);

	test_consumer_subscribe(rk, topic);

	while (cnt < msgcnt) {
		rd_kafka_message_t *rkm;

		rkm = rd_kafka_consumer_poll(rk, 10*1000);
		if (!rkm)
			continue;

		if (rkm->err == RD_KAFKA_RESP_ERR__TIMED_OUT)
			TEST_FAIL("%s: Timed out waiting for message %d", what,cnt);
                else if (rkm->err)
			TEST_FAIL("%s: Consumer error: %s",
				  what, rd_kafka_message_errstr(rkm));

		if (rkm->offset != expected_offset)
			TEST_FAIL("%s: Received message offset %"PRId64
				  ", expected %"PRId64" at msgcnt %d/%d\n",
				  what, rkm->offset, expected_offset,
				  cnt, msgcnt);

		rd_kafka_message_destroy(rkm);
		expected_offset++;
		cnt++;
	}


	TEST_SAY("%s: phase 2: complete\n", what);
	test_consumer_close(rk);
	rd_kafka_destroy(rk);
	

	TIMING_STOP(&t_all);
}


static void empty_offset_commit_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
				    rd_kafka_topic_partition_list_t *offsets,
				    void *opaque) {
	rd_kafka_resp_err_t expected = *(rd_kafka_resp_err_t *)opaque;
	int valid_offsets = 0;
	int i;

	TEST_SAY("Offset commit callback for %d partitions: %s (expecting %s)\n",
		 offsets ? offsets->cnt : 0,
		 rd_kafka_err2str(err),
		 rd_kafka_err2str(expected));

	if (expected != err)
		TEST_FAIL("Offset commit cb: expected %s, got %s",
			  rd_kafka_err2str(expected),
			  rd_kafka_err2str(err));

	for (i = 0 ; i < offsets->cnt ; i++) {
		TEST_SAY("committed: %s [%"PRId32"] offset %"PRId64
			 ": %s\n",
			 offsets->elems[i].topic,
			 offsets->elems[i].partition,
			 offsets->elems[i].offset,
			 rd_kafka_err2str(offsets->elems[i].err));

		if (expected == RD_KAFKA_RESP_ERR_NO_ERROR)
			TEST_ASSERT(offsets->elems[i].err == expected);
		if (offsets->elems[i].offset > 0)
			valid_offsets++;
	}

	if (expected == RD_KAFKA_RESP_ERR_NO_ERROR) {
		/* If no error is expected we instead expect one proper offset
		 * to have been committed. */
		TEST_ASSERT(valid_offsets > 0);
	}
}


/**
 * Trigger an empty cgrp commit (issue #803)
 */
static void do_empty_commit (void) {
	rd_kafka_t *rk;
	char group_id[64];
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *tconf;
	rd_kafka_resp_err_t err, expect;

	test_conf_init(&conf, &tconf, 20);
	test_conf_set(conf, "enable.auto.commit", "false");
	test_topic_conf_set(tconf, "auto.offset.reset", "earliest");
	test_str_id_generate(group_id, sizeof(group_id));

	TEST_SAY(_C_MAG "[ do_empty_commit group.id %s ]\n", group_id);

	rk = test_create_consumer(group_id, NULL, conf, tconf);

	test_consumer_subscribe(rk, topic);

	test_consumer_poll("consume", rk, testid, -1, -1, 100, NULL);

	TEST_SAY("First commit\n");
	expect = RD_KAFKA_RESP_ERR_NO_ERROR;
	err = rd_kafka_commit_queue(rk, NULL, NULL,
				    empty_offset_commit_cb, &expect);
	if (err != expect)
		TEST_FAIL("commit failed: %s", rd_kafka_err2str(err));
	else
		TEST_SAY("First commit returned %s\n",
			 rd_kafka_err2str(err));

	TEST_SAY("Second commit, should be empty\n");
	expect = RD_KAFKA_RESP_ERR__NO_OFFSET;
	err = rd_kafka_commit_queue(rk, NULL, NULL,
				    empty_offset_commit_cb, &expect);
	if (err != RD_KAFKA_RESP_ERR__NO_OFFSET)
		TEST_FAIL("unexpected commit result, wanted NO_OFFSET, got: %s",
			  rd_kafka_err2str(err));
	else
		TEST_SAY("Second commit returned %s\n",
			 rd_kafka_err2str(err));

	test_consumer_close(rk);

	rd_kafka_destroy(rk);
}


/**
 * Commit non-existent topic (issue #704)
 */
static void nonexist_offset_commit_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
				       rd_kafka_topic_partition_list_t *offsets,
				       void *opaque) {
	int i;
	int failed_offsets = 0;

	TEST_SAY("Offset commit callback for %d partitions: %s\n",
		 offsets ? offsets->cnt : 0,
		 rd_kafka_err2str(err));

	TEST_ASSERT(offsets != NULL);

	for (i = 0 ; i < offsets->cnt ; i++) {
		TEST_SAY("committed: %s [%"PRId32"] offset %"PRId64
			 ": %s\n",
			 offsets->elems[i].topic,
			 offsets->elems[i].partition,
			 offsets->elems[i].offset,
			 rd_kafka_err2str(offsets->elems[i].err));
		failed_offsets += offsets->elems[i].err ? 1 : 0;
	}

	TEST_ASSERT(err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,
		    "expected unknown Topic or partition, not %s", rd_kafka_err2str(err));
	TEST_ASSERT(offsets->cnt == 2, "expected %d offsets", offsets->cnt);
	TEST_ASSERT(failed_offsets == offsets->cnt,
		    "expected %d offsets to have failed, got %d",
		    offsets->cnt, failed_offsets);
}

static void do_nonexist_commit (void) {
	rd_kafka_t *rk;
	char group_id[64];
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *tconf;
	rd_kafka_topic_partition_list_t *offsets;
	const char *unk_topic = test_mk_topic_name(__FUNCTION__, 1);
	rd_kafka_resp_err_t err;

	test_conf_init(&conf, &tconf, 20);
        /* Offset commit deferrals when the broker is down is limited to
         * session.timeout.ms. With 0.9 brokers and api.version.request=true
         * the initial connect to all brokers will take 10*2 seconds
         * and the commit_queue() below will time out too quickly.
         * Set the session timeout high here to avoid it. */
        test_conf_set(conf, "session.timeout.ms", "60000");

	test_str_id_generate(group_id, sizeof(group_id));
        test_conf_set(conf, "group.id", group_id);

        rd_kafka_conf_set_default_topic_conf(conf, tconf);

        TEST_SAY(_C_MAG "[ do_nonexist_commit group.id %s ]\n", group_id);

        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);
        rd_kafka_poll_set_consumer(rk);

	TEST_SAY("Try nonexist commit\n");
	offsets = rd_kafka_topic_partition_list_new(2);
	rd_kafka_topic_partition_list_add(offsets, unk_topic, 0)->offset = 123;
	rd_kafka_topic_partition_list_add(offsets, unk_topic, 1)->offset = 456;

	err = rd_kafka_commit_queue(rk, offsets, NULL,
				    nonexist_offset_commit_cb, NULL);
	TEST_SAY("nonexist commit returned %s\n", rd_kafka_err2str(err));
	if (err != RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART)
		TEST_FAIL("commit() should give UnknownTopicOrPart, not: %s",
			  rd_kafka_err2str(err));

	rd_kafka_topic_partition_list_destroy(offsets);

	test_consumer_close(rk);

	rd_kafka_destroy(rk);
}


int main_0030_offset_commit (int argc, char **argv) {

	topic = test_mk_topic_name(__FUNCTION__, 1);
	testid = test_produce_msgs_easy(topic, 0, partition, msgcnt);

	do_offset_test("AUTO.COMMIT & AUTO.STORE",
		       1 /* enable.auto.commit */,
		       1 /* enable.auto.offset.store */,
		       0 /* not used. */);

	do_offset_test("AUTO.COMMIT & MANUAL.STORE",
		       1 /* enable.auto.commit */,
		       0 /* enable.auto.offset.store */,
		       0 /* not used */);

	do_offset_test("MANUAL.COMMIT.ASYNC & AUTO.STORE",
		       0 /* enable.auto.commit */,
		       1 /* enable.auto.offset.store */,
		       1 /* async */);

	do_offset_test("MANUAL.COMMIT.SYNC & AUTO.STORE",
		       0 /* enable.auto.commit */,
		       1 /* enable.auto.offset.store */,
		       0 /* async */);

	do_offset_test("MANUAL.COMMIT.ASYNC & MANUAL.STORE",
		       0 /* enable.auto.commit */,
		       0 /* enable.auto.offset.store */,
		       1 /* sync */);

	do_offset_test("MANUAL.COMMIT.SYNC & MANUAL.STORE",
		       0 /* enable.auto.commit */,
		       0 /* enable.auto.offset.store */,
		       0 /* sync */);

	do_empty_commit();

	do_nonexist_commit();

        return 0;
}
