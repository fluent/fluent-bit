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
 * KafkaConsumer: regex topic subscriptions
 */



struct expect {
	char *name;           /* sub-test name */
	const char *sub[4];  /* subscriptions */
	const char *exp[4];  /* expected topics */
        int         exp_err; /* expected error from subscribe() */
	int         stat[4]; /* per exp status */
	int         fails;
	enum {
		_EXP_NONE,
		_EXP_FAIL,
		_EXP_OK,
		_EXP_ASSIGN,
		_EXP_REVOKE,
		_EXP_ASSIGNED,
		_EXP_REVOKED,
	} result;
};

static struct expect *exp_curr;

static uint64_t testid;

static void expect_match (struct expect *exp,
			  const rd_kafka_topic_partition_list_t *parts) {
	int i;
	int e = 0;
	int fails = 0;

	memset(exp->stat, 0, sizeof(exp->stat));

	for (i = 0 ; i < parts->cnt ; i++) {
		int found = 0;
		e = 0;
		while (exp->exp[e]) {
			if (!strcmp(parts->elems[i].topic, exp->exp[e])) {
				exp->stat[e]++;
				found++;
			}
			e++;
		}

		if (!found) {
			TEST_WARN("%s: got unexpected topic match: %s\n",
				  exp->name, parts->elems[i].topic);
			fails++;
		}
	}


	e = 0;
	while (exp->exp[e]) {
		if (!exp->stat[e]) {
			TEST_WARN("%s: expected topic not "
				  "found in assignment: %s\n",
				  exp->name, exp->exp[e]);
			fails++;
		} else {
			TEST_SAY("%s: expected topic %s seen in assignment\n",
				 exp->name, exp->exp[e]);
		}
		e++;
	}

	exp->fails += fails;
	if (fails) {
		TEST_WARN("%s: see %d previous failures\n", exp->name, fails);
		exp->result = _EXP_FAIL;
	} else {
		TEST_SAY(_C_MAG "[ %s: assignment matched ]\n", exp->name);
		exp->result = _EXP_OK;
	}

}

static void rebalance_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
			  rd_kafka_topic_partition_list_t *parts, void *opaque){
	struct expect *exp = exp_curr;

	TEST_ASSERT(exp_curr, "exp_curr not set");

	TEST_SAY("rebalance_cb: %s with %d partition(s)\n",
		 rd_kafka_err2str(err), parts->cnt);
	test_print_partition_list(parts);

	switch (err)
	{
	case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
		/* Check that provided partitions match our expectations */
		if (exp->result != _EXP_ASSIGN) {
			TEST_WARN("%s: rebalance called while expecting %d: "
				  "too many or undesired assignment(s?\n",
				  exp->name, exp->result);
		}
		expect_match(exp, parts);
		test_consumer_assign("rebalance", rk, parts);
		exp->result = _EXP_ASSIGNED;
		break;

	case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
		if (exp->result != _EXP_REVOKE) {
			TEST_WARN("%s: rebalance called while expecting %d: "
				  "too many or undesired assignment(s?\n",
				  exp->name, exp->result);
		}

		test_consumer_unassign("rebalance", rk);
		exp->result = _EXP_REVOKED;
		break;

	default:
		TEST_FAIL("rebalance_cb: error: %s", rd_kafka_err2str(err));
	}
}


static int test_subscribe (rd_kafka_t *rk, struct expect *exp) {
	rd_kafka_resp_err_t err;
	rd_kafka_topic_partition_list_t *tlist;
	int i;
	test_timing_t t_sub, t_assign, t_unsub;

	exp_curr = exp;

	test_timeout_set((test_session_timeout_ms/1000) * 3);

	tlist = rd_kafka_topic_partition_list_new(4);
	TEST_SAY(_C_MAG "[ %s: begin ]\n", exp->name);
	i = 0;
	TEST_SAY("Topic subscription:\n");
	while (exp->sub[i]) {
		TEST_SAY("%s:  %s\n", exp->name, exp->sub[i]);
		rd_kafka_topic_partition_list_add(tlist, exp->sub[i],
						  RD_KAFKA_PARTITION_UA);
		i++;
	}

	/* Subscribe */
	TIMING_START(&t_sub, "subscribe");
	err = rd_kafka_subscribe(rk, tlist);
	TIMING_STOP(&t_sub);
	TEST_ASSERT(err == exp->exp_err,
                    "subscribe() failed: %s (expected %s)",
                    rd_kafka_err2str(err), rd_kafka_err2str(exp->exp_err));

	if (exp->exp[0]) {
		/* Wait for assignment, actual messages are ignored. */
		exp->result = _EXP_ASSIGN;
		TEST_SAY("%s: waiting for assignment\n", exp->name);
		TIMING_START(&t_assign, "assignment");
		while (exp->result == _EXP_ASSIGN)
			test_consumer_poll_once(rk, NULL, 1000);
		TIMING_STOP(&t_assign);
		TEST_ASSERT(exp->result == _EXP_ASSIGNED,
			    "got %d instead of assignment", exp->result);

	} else {
		/* Not expecting any assignment */
		int64_t ts_end = test_clock() + 5000;
		exp->result = _EXP_NONE; /* Not expecting a rebalance */
		while (exp->result == _EXP_NONE && test_clock() < ts_end)
			test_consumer_poll_once(rk, NULL, 1000);
		TEST_ASSERT(exp->result == _EXP_NONE);
	}

	/* Unsubscribe */
	TIMING_START(&t_unsub, "unsubscribe");
	err = rd_kafka_unsubscribe(rk);
	TIMING_STOP(&t_unsub);
	TEST_ASSERT(!err, "unsubscribe() failed: %s", rd_kafka_err2str(err));

	rd_kafka_topic_partition_list_destroy(tlist);

	if (exp->exp[0]) {
		/* Wait for revoke, actual messages are ignored. */
		TEST_SAY("%s: waiting for revoke\n", exp->name);
		exp->result = _EXP_REVOKE;
		TIMING_START(&t_assign, "revoke");
		while (exp->result != _EXP_REVOKED)
			test_consumer_poll_once(rk, NULL, 1000);
		TIMING_STOP(&t_assign);
		TEST_ASSERT(exp->result == _EXP_REVOKED,
			    "got %d instead of revoke", exp->result);
	} else {
		/* Not expecting any revoke */
		int64_t ts_end = test_clock() + 5000;
		exp->result = _EXP_NONE; /* Not expecting a rebalance */
		while (exp->result == _EXP_NONE && test_clock() < ts_end)
			test_consumer_poll_once(rk, NULL, 1000);
		TEST_ASSERT(exp->result == _EXP_NONE);
	}

	TEST_SAY(_C_MAG "[ %s: done with %d failures ]\n", exp->name, exp->fails);

	return exp->fails;
}


static int do_test (const char *assignor) {
	static char topics[3][128];
	static char nonexist_topic[128];
	const int topic_cnt = 3;
	rd_kafka_t *rk;
	const int msgcnt = 10;
	int i;
	char groupid[64];
	int fails = 0;
	rd_kafka_conf_t *conf;

	if (!test_check_builtin("regex")) {
		TEST_SKIP("regex support not built in\n");
		return 0;
	}

	testid = test_id_generate();
	test_str_id_generate(groupid, sizeof(groupid));

	rd_snprintf(topics[0], sizeof(topics[0]),
		    "%s_%s",
		    test_mk_topic_name("regex_subscribe_TOPIC_0001_UNO", 0),
		    groupid);
	rd_snprintf(topics[1], sizeof(topics[1]),
		    "%s_%s",
		    test_mk_topic_name("regex_subscribe_topic_0002_dup", 0),
		    groupid);
	rd_snprintf(topics[2], sizeof(topics[2]),
		    "%s_%s",
		    test_mk_topic_name("regex_subscribe_TOOTHPIC_0003_3", 0),
		    groupid);

        /* To avoid auto topic creation to kick in we use
         * an invalid topic name. */
	rd_snprintf(nonexist_topic, sizeof(nonexist_topic),
		    "%s_%s",
		    test_mk_topic_name("regex_subscribe_NONEXISTENT_0004_IV#!",
                                       0),
		    groupid);

	/* Produce messages to topics to ensure creation. */
	for (i = 0 ; i < topic_cnt ; i++)
		test_produce_msgs_easy(topics[i], testid,
				       RD_KAFKA_PARTITION_UA, msgcnt);

	test_conf_init(&conf, NULL, 20);
	test_conf_set(conf, "partition.assignment.strategy", assignor);
	/* Speed up propagation of new topics */
	test_conf_set(conf, "topic.metadata.refresh.interval.ms", "5000");

	/* Create a single consumer to handle all subscriptions.
	 * Has the nice side affect of testing multiple subscriptions. */
	rk = test_create_consumer(groupid, rebalance_cb, conf, NULL);

	/*
	 * Test cases
	 */
	{
		struct expect expect = {
			.name = rd_strdup(tsprintf("%s: no regexps (0&1)",
						   assignor)),
			.sub = { topics[0], topics[1], NULL },
			.exp = { topics[0], topics[1], NULL }
		};

		fails += test_subscribe(rk, &expect);
		rd_free(expect.name);
	}

	{
		struct expect expect = {
			.name = rd_strdup(tsprintf("%s: no regexps "
						   "(no matches)",
						   assignor)),
			.sub = { nonexist_topic, NULL },
			.exp = { NULL }
		};

		fails += test_subscribe(rk, &expect);
		rd_free(expect.name);
	}

	{
		struct expect expect = {
			.name = rd_strdup(tsprintf("%s: regex all", assignor)),
			.sub = { rd_strdup(tsprintf("^.*_%s", groupid)), NULL },
			.exp = { topics[0], topics[1], topics[2], NULL }
		};

		fails += test_subscribe(rk, &expect);
		rd_free(expect.name);
		rd_free((void*)expect.sub[0]);
	}

	{
		struct expect expect = {
			.name = rd_strdup(tsprintf("%s: regex 0&1", assignor)),
			.sub = { rd_strdup(tsprintf("^.*[tToOpPiIcC]_0+[12]_[^_]+_%s",
						    groupid)), NULL },
			.exp = { topics[0], topics[1], NULL }
		};

		fails += test_subscribe(rk, &expect);
		rd_free(expect.name);
		rd_free((void*)expect.sub[0]);
	}

	{
		struct expect expect = {
			.name = rd_strdup(tsprintf("%s: regex 2", assignor)),
			.sub = { rd_strdup(tsprintf("^.*TOOTHPIC_000._._%s",
						    groupid)), NULL },
			.exp = { topics[2], NULL }
		};

		fails += test_subscribe(rk, &expect);
		rd_free(expect.name);
		rd_free((void *)expect.sub[0]);
	}

	{
		struct expect expect = {
			.name = rd_strdup(tsprintf("%s: regex 2 and "
						   "nonexistent(not seen)",
						   assignor)),
			.sub = { rd_strdup(tsprintf("^.*_000[34]_..?_%s",
						    groupid)), NULL },
			.exp = { topics[2], NULL }
		};

		fails += test_subscribe(rk, &expect);
		rd_free(expect.name);
		rd_free((void *)expect.sub[0]);
	}

	{
		struct expect expect = {
			.name = rd_strdup(tsprintf("%s: broken regex (no matches)",
						   assignor)),
			.sub = { "^.*[0", NULL },
			.exp = { NULL },
                        .exp_err = RD_KAFKA_RESP_ERR__INVALID_ARG
		};

		fails += test_subscribe(rk, &expect);
		rd_free(expect.name);
	}


	test_consumer_close(rk);

	rd_kafka_destroy(rk);

	if (fails)
		TEST_FAIL("See %d previous failures", fails);

        return 0;
}


int main_0033_regex_subscribe (int argc, char **argv) {
	do_test("range");
	do_test("roundrobin");
	return 0;
}


/**
 * @brief Subscription API tests that dont require a broker
 */
int main_0033_regex_subscribe_local (int argc, char **argv) {
        rd_kafka_topic_partition_list_t *valids, *invalids, *none,
                *empty, *alot;
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_resp_err_t err;
        char errstr[256];
        int i;

        valids = rd_kafka_topic_partition_list_new(0);
        invalids = rd_kafka_topic_partition_list_new(100);
        none = rd_kafka_topic_partition_list_new(1000);
        empty = rd_kafka_topic_partition_list_new(5);
        alot = rd_kafka_topic_partition_list_new(1);

        rd_kafka_topic_partition_list_add(valids, "not_a_regex", 0);
        rd_kafka_topic_partition_list_add(valids, "^My[vV]alid..regex+", 0);
        rd_kafka_topic_partition_list_add(valids, "^another_one$", 55);

        rd_kafka_topic_partition_list_add(invalids, "not_a_regex", 0);
        rd_kafka_topic_partition_list_add(invalids, "^My[vV]alid..regex+", 0);
        rd_kafka_topic_partition_list_add(invalids, "^a[b", 99);

        rd_kafka_topic_partition_list_add(empty, "not_a_regex", 0);
        rd_kafka_topic_partition_list_add(empty, "", 0);
        rd_kafka_topic_partition_list_add(empty, "^ok", 0);

        for (i = 0 ; i < 10000 ; i++) {
                char topic[32];
                rd_snprintf(topic, sizeof(topic), "^Va[lLid]_regex_%d$", i);
                rd_kafka_topic_partition_list_add(alot, topic, i);
        }

        conf = rd_kafka_conf_new();
        test_conf_set(conf, "group.id", "group");
        test_conf_set(conf, "client.id", test_curr->name);

        rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
        if (!rk)
                TEST_FAIL("Failed to create consumer: %s", errstr);

        err = rd_kafka_subscribe(rk, valids);
        TEST_ASSERT(!err, "valids failed: %s", rd_kafka_err2str(err));

        err = rd_kafka_subscribe(rk, invalids);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                    "invalids failed with wrong return: %s",
                    rd_kafka_err2str(err));

        err = rd_kafka_subscribe(rk, none);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                    "none failed with wrong return: %s", rd_kafka_err2str(err));

        err = rd_kafka_subscribe(rk, empty);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                    "empty failed with wrong return: %s",
                    rd_kafka_err2str(err));

        err = rd_kafka_subscribe(rk, alot);
        TEST_ASSERT(!err, "alot failed: %s", rd_kafka_err2str(err));

        rd_kafka_consumer_close(rk);
        rd_kafka_destroy(rk);

        rd_kafka_topic_partition_list_destroy(valids);
        rd_kafka_topic_partition_list_destroy(invalids);
        rd_kafka_topic_partition_list_destroy(none);
        rd_kafka_topic_partition_list_destroy(empty);
        rd_kafka_topic_partition_list_destroy(alot);

        return 0;
}
