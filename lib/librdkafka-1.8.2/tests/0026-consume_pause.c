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
 * Consumer: pause and resume.
 * Make sure no messages are lost or duplicated.
 */



static int consume_pause (void) {
	const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        const int partition_cnt = 3;
	rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *tconf;
	rd_kafka_topic_partition_list_t *topics;
	rd_kafka_resp_err_t err;
        const int msgcnt = 1000;
        uint64_t testid;
	int it, iterations = 3;
	int msg_base = 0;
	int fails = 0;
        char group_id[32];

        test_conf_init(&conf, &tconf,
                       60 + (test_session_timeout_ms * 3 / 1000));
        test_conf_set(conf, "enable.partition.eof", "true");
	test_topic_conf_set(tconf, "auto.offset.reset", "smallest");

        test_create_topic(NULL, topic, partition_cnt, 1);

        /* Produce messages */
        testid = test_produce_msgs_easy(topic, 0,
                                        RD_KAFKA_PARTITION_UA, msgcnt);

	topics = rd_kafka_topic_partition_list_new(1);
	rd_kafka_topic_partition_list_add(topics, topic, -1);

	for (it = 0 ; it < iterations ; it++) {
		const int pause_cnt = 5;
		int per_pause_msg_cnt = msgcnt / pause_cnt;
                const int pause_time = 1200 /* 1.2s */;
                int eof_cnt = -1;
		int pause;
		rd_kafka_topic_partition_list_t *parts;
		test_msgver_t mv_all;
		int j;

		test_msgver_init(&mv_all, testid); /* All messages */

                /* On the last iteration reuse the previous group.id
                 * to make consumer start at committed offsets which should
                 * also be EOF. This to trigger #1307. */
                if (it < iterations-1)
                        test_str_id_generate(group_id, sizeof(group_id));
                else {
                        TEST_SAY("Reusing previous group.id %s\n", group_id);
                        per_pause_msg_cnt = 0;
                        eof_cnt = partition_cnt;
                }

		TEST_SAY("Iteration %d/%d, using group.id %s, "
                         "expecting %d messages/pause and %d EOFs\n",
                         it, iterations-1, group_id,
                         per_pause_msg_cnt, eof_cnt);

                rk = test_create_consumer(group_id, NULL,
                                          rd_kafka_conf_dup(conf),
                                          rd_kafka_topic_conf_dup(tconf));


		TEST_SAY("Subscribing to %d topic(s): %s\n",
			 topics->cnt, topics->elems[0].topic);
		if ((err = rd_kafka_subscribe(rk, topics)))
			TEST_FAIL("Failed to subscribe: %s\n",
				  rd_kafka_err2str(err));


		for (pause = 0 ; pause < pause_cnt ; pause++) {
			int rcnt;
			test_timing_t t_assignment;
			test_msgver_t mv;

			test_msgver_init(&mv, testid);
			mv.fwd = &mv_all;

			/* Consume sub-part of the messages. */
			TEST_SAY("Pause-Iteration #%d: Consume %d messages at "
				 "msg_base %d\n", pause, per_pause_msg_cnt,
				 msg_base);
			rcnt = test_consumer_poll("consume.part", rk, testid,
                                                  eof_cnt,
						  msg_base,
                                                  per_pause_msg_cnt == 0 ?
                                                  -1 : per_pause_msg_cnt,
						  &mv);

			TEST_ASSERT(rcnt == per_pause_msg_cnt,
				    "expected %d messages, got %d",
				    per_pause_msg_cnt, rcnt);

			test_msgver_verify("pause.iteration",
					   &mv, TEST_MSGVER_PER_PART,
					   msg_base, per_pause_msg_cnt);
			test_msgver_clear(&mv);

			msg_base += per_pause_msg_cnt;

			TIMING_START(&t_assignment, "rd_kafka_assignment()");
			if ((err = rd_kafka_assignment(rk, &parts)))
				TEST_FAIL("failed to get assignment: %s\n",
					  rd_kafka_err2str(err));
			TIMING_STOP(&t_assignment);

			TEST_ASSERT(parts->cnt > 0,
				    "parts->cnt %d, expected > 0", parts->cnt);

			TEST_SAY("Now pausing %d partition(s) for %dms\n",
				 parts->cnt, pause_time);
			if ((err = rd_kafka_pause_partitions(rk, parts)))
				TEST_FAIL("Failed to pause: %s\n",
					  rd_kafka_err2str(err));

			/* Check per-partition errors */
			for (j = 0 ; j < parts->cnt ; j++) {
				if (parts->elems[j].err) {
					TEST_WARN("pause failure for "
						  "%s %"PRId32"]: %s\n",
						  parts->elems[j].topic,
						  parts->elems[j].partition,
						  rd_kafka_err2str(
							  parts->elems[j].err));
					fails++;
				}
			}
			TEST_ASSERT(fails == 0, "See previous warnings\n");

			TEST_SAY("Waiting for %dms, should not receive any "
				 "messages during this time\n", pause_time);
			
			test_consumer_poll_no_msgs("silence.while.paused",
						   rk, testid, pause_time);

			TEST_SAY("Resuming %d partitions\n", parts->cnt);
			if ((err = rd_kafka_resume_partitions(rk, parts)))
				TEST_FAIL("Failed to resume: %s\n",
					  rd_kafka_err2str(err));

			/* Check per-partition errors */
			for (j = 0 ; j < parts->cnt ; j++) {
				if (parts->elems[j].err) {
					TEST_WARN("resume failure for "
						  "%s %"PRId32"]: %s\n",
						  parts->elems[j].topic,
						  parts->elems[j].partition,
						  rd_kafka_err2str(
							  parts->elems[j].err));
					fails++;
				}
			}
			TEST_ASSERT(fails == 0, "See previous warnings\n");

			rd_kafka_topic_partition_list_destroy(parts);
		}

                if (per_pause_msg_cnt > 0)
                        test_msgver_verify("all.msgs", &mv_all,
                                           TEST_MSGVER_ALL_PART, 0, msgcnt);
                else
                        test_msgver_verify("all.msgs", &mv_all,
                                           TEST_MSGVER_ALL_PART, 0, 0);
                        test_msgver_clear(&mv_all);
		
		/* Should now not see any more messages. */
		test_consumer_poll_no_msgs("end.exp.no.msgs", rk, testid, 3000);
		
		test_consumer_close(rk);

		/* Hangs if bug isn't fixed */
		rd_kafka_destroy(rk);
	}

	rd_kafka_topic_partition_list_destroy(topics);
        rd_kafka_conf_destroy(conf);
	rd_kafka_topic_conf_destroy(tconf);

        return 0;
}



/**
 * @brief Verify that the paused partition state is not used after
 *        the partition has been re-assigned.
 *
 * 1. Produce N messages
 * 2. Consume N/4 messages
 * 3. Pause partitions
 * 4. Manually commit offset N/2
 * 5. Unassign partitions
 * 6. Assign partitions again
 * 7. Verify that consumption starts at N/2 and not N/4
 */
static int consume_pause_resume_after_reassign (void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        const int32_t partition = 0;
        const int msgcnt = 4000;
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_partition_list_t *partitions, *pos;
        rd_kafka_resp_err_t err;
        int exp_msg_cnt;
        uint64_t testid;
        int r;
        int msg_base = 0;
        test_msgver_t mv;
        rd_kafka_topic_partition_t *toppar;

        test_conf_init(&conf, NULL, 60);

        test_create_topic(NULL, topic, (int)partition+1, 1);

        /* Produce messages */
        testid = test_produce_msgs_easy(topic, 0, partition, msgcnt);

        /* Set start offset to beginning */
        partitions = rd_kafka_topic_partition_list_new(1);
        toppar = rd_kafka_topic_partition_list_add(partitions, topic,
                                                   partition);
        toppar->offset = RD_KAFKA_OFFSET_BEGINNING;


        /**
         * Create consumer.
         */
        test_conf_set(conf, "enable.partition.eof", "true");
        rk = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_assign("assign", rk, partitions);


        exp_msg_cnt = msgcnt/4;
        TEST_SAY("Consuming first quarter (%d) of messages\n", exp_msg_cnt);
        test_msgver_init(&mv, testid);
        r = test_consumer_poll("consume.first.quarter", rk, testid, 0,
                               msg_base, exp_msg_cnt, &mv);
        TEST_ASSERT(r == exp_msg_cnt,
                    "expected %d messages, got %d", exp_msg_cnt, r);


        TEST_SAY("Pausing partitions\n");
        if ((err = rd_kafka_pause_partitions(rk, partitions)))
                TEST_FAIL("Failed to pause: %s", rd_kafka_err2str(err));

        TEST_SAY("Verifying pause, should see no new messages...\n");
        test_consumer_poll_no_msgs("silence.while.paused", rk, testid, 3000);

        test_msgver_verify("first.quarter", &mv, TEST_MSGVER_ALL_PART,
                           msg_base, exp_msg_cnt);
        test_msgver_clear(&mv);


        /* Check position */
        pos = rd_kafka_topic_partition_list_copy(partitions);
        if ((err = rd_kafka_position(rk, pos)))
                TEST_FAIL("position() failed: %s", rd_kafka_err2str(err));

        TEST_ASSERT(!pos->elems[0].err,
                    "position() returned error for our partition: %s",
                    rd_kafka_err2str(pos->elems[0].err));
        TEST_SAY("Current application consume position is %"PRId64"\n",
                 pos->elems[0].offset);
        TEST_ASSERT(pos->elems[0].offset == (int64_t)exp_msg_cnt,
                    "expected position %"PRId64", not %"PRId64,
                    (int64_t)exp_msg_cnt, pos->elems[0].offset);
        rd_kafka_topic_partition_list_destroy(pos);


        toppar->offset = (int64_t)(msgcnt/2);
        TEST_SAY("Committing (yet unread) offset %"PRId64"\n", toppar->offset);
        if ((err = rd_kafka_commit(rk, partitions, 0/*sync*/)))
                TEST_FAIL("Commit failed: %s", rd_kafka_err2str(err));


        TEST_SAY("Unassigning\n");
        test_consumer_unassign("Unassign", rk);

        /* Set start offset to INVALID so that the standard start offset
         * logic kicks in. */
        toppar->offset = RD_KAFKA_OFFSET_INVALID;

        TEST_SAY("Reassigning\n");
        test_consumer_assign("Reassign", rk, partitions);


        TEST_SAY("Resuming partitions\n");
        if ((err = rd_kafka_resume_partitions(rk, partitions)))
                TEST_FAIL("Failed to resume: %s", rd_kafka_err2str(err));

        msg_base = msgcnt / 2;
        exp_msg_cnt = msgcnt / 2;
        TEST_SAY("Consuming second half (%d) of messages at msg_base %d\n",
                 exp_msg_cnt, msg_base);
        test_msgver_init(&mv, testid);
        r = test_consumer_poll("consume.second.half", rk, testid, 1/*exp eof*/,
                               msg_base, exp_msg_cnt, &mv);
        TEST_ASSERT(r == exp_msg_cnt,
                    "expected %d messages, got %d", exp_msg_cnt, r);

        test_msgver_verify("second.half", &mv, TEST_MSGVER_ALL_PART,
                           msg_base, exp_msg_cnt);
        test_msgver_clear(&mv);


        rd_kafka_topic_partition_list_destroy(partitions);

        test_consumer_close(rk);

        rd_kafka_destroy(rk);

        return 0;
}


static void rebalance_cb (rd_kafka_t *rk,
                          rd_kafka_resp_err_t err,
                          rd_kafka_topic_partition_list_t *parts,
                          void *opaque) {
        rd_kafka_resp_err_t err2;

        switch (err)
        {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                /* Set start offset to beginning,
                 * while auto.offset.reset is default at `latest`. */

                parts->elems[0].offset = RD_KAFKA_OFFSET_BEGINNING;
                test_consumer_assign("rebalance", rk, parts);
                TEST_SAY("Pausing partitions\n");
                if ((err2 = rd_kafka_pause_partitions(rk, parts)))
                        TEST_FAIL("Failed to pause: %s",
                                  rd_kafka_err2str(err2));
                TEST_SAY("Resuming partitions\n");
                if ((err2 = rd_kafka_resume_partitions(rk, parts)))
                        TEST_FAIL("Failed to pause: %s",
                                  rd_kafka_err2str(err2));
                break;
        default:
                test_consumer_unassign("rebalance", rk);
                break;
        }
}


/**
 * @brief Verify that the assigned offset is used after pause+resume
 *        if no messages were consumed prior to pause. #2105
 *
 * We do this by setting the start offset to BEGINNING in the rebalance_cb
 * and relying on auto.offset.reset=latest (default) to catch the failure case
 * where the assigned offset was not honoured.
 */
static int consume_subscribe_assign_pause_resume (void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        const int32_t partition = 0;
        const int msgcnt = 1;
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        uint64_t testid;
        int r;
        test_msgver_t mv;

        TEST_SAY(_C_CYA "[ %s ]\n", __FUNCTION__);

        test_conf_init(&conf, NULL, 20);

        test_create_topic(NULL, topic, (int)partition+1, 1);

        /* Produce messages */
        testid = test_produce_msgs_easy(topic, 0, partition, msgcnt);

        /**
         * Create consumer.
         */
        rd_kafka_conf_set_rebalance_cb(conf, rebalance_cb);
        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "enable.partition.eof", "true");
        rk = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(rk, topic);

        test_msgver_init(&mv, testid);
        r = test_consumer_poll("consume", rk, testid, 1/*exp eof*/,
                               0, msgcnt, &mv);
        TEST_ASSERT(r == msgcnt,
                    "expected %d messages, got %d", msgcnt, r);

        test_msgver_verify("consumed", &mv, TEST_MSGVER_ALL_PART, 0, msgcnt);
        test_msgver_clear(&mv);


        test_consumer_close(rk);

        rd_kafka_destroy(rk);

        return 0;
}


int main_0026_consume_pause (int argc, char **argv) {
        int fails = 0;

        if (test_can_create_topics(1)) {
                fails += consume_pause();
                fails += consume_pause_resume_after_reassign();
                fails += consume_subscribe_assign_pause_resume();
        }

        if (fails > 0)
                TEST_FAIL("See %d previous error(s)\n", fails);

        return 0;
}
