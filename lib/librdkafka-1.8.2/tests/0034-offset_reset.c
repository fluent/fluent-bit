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

#include "../src/rdkafka_protocol.h"


/**
 * Issue #559: make sure auto.offset.reset works with invalid offsets.
 */


static void do_test_reset (const char *topic, int partition,
			   const char *reset, int64_t initial_offset,
			   int exp_eofcnt, int exp_msgcnt, int exp_errcnt,
                           int exp_resetcnt) {
	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;
	int eofcnt = 0, msgcnt = 0, errcnt = 0, resetcnt = 0;
        rd_kafka_conf_t *conf;

	TEST_SAY("Test auto.offset.reset=%s, "
		 "expect %d msgs, %d EOFs, %d errors, %d resets\n",
		 reset, exp_msgcnt, exp_eofcnt, exp_errcnt, exp_resetcnt);

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "enable.partition.eof", "true");

	rk = test_create_consumer(NULL, NULL, conf, NULL);
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
                } else if (rkm->err == RD_KAFKA_RESP_ERR__AUTO_OFFSET_RESET) {
                        TEST_SAY("%s: auto.offset.reset error at offset %"PRId64
                                 ": %s: %s\n",
                                 reset, rkm->offset,
                                 rd_kafka_err2name(rkm->err),
                                 rd_kafka_message_errstr(rkm));
                        resetcnt++;
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
		    msgcnt == exp_msgcnt &&
                    resetcnt == exp_resetcnt)
			break;
		else if (eofcnt > exp_eofcnt ||
			 errcnt > exp_errcnt ||
			 msgcnt > exp_msgcnt ||
                         resetcnt > exp_resetcnt)
			TEST_FAIL("%s: unexpected: "
				  "%d/%d messages, %d/%d EOFs, %d/%d errors, "
                                  "%d/%d resets\n",
				  reset,
				  msgcnt, exp_msgcnt,
				  eofcnt, exp_eofcnt,
				  errcnt, exp_errcnt,
                                  resetcnt, exp_resetcnt);
	}

	TEST_SAY("%s: Done: "
		 "%d/%d messages, %d/%d EOFs, %d/%d errors, %d/%d resets\n",
		 reset,
		 msgcnt, exp_msgcnt,
		 eofcnt, exp_eofcnt,
		 errcnt, exp_errcnt,
                 resetcnt, exp_resetcnt);

	test_consumer_stop(reset, rkt, partition);

	rd_kafka_topic_destroy(rkt);
	rd_kafka_destroy(rk);
}

int main_0034_offset_reset (int argc, char **argv) {
	const char *topic = test_mk_topic_name(__FUNCTION__, 1);
	const int partition = 0;
        const int msgcnt = test_quick ? 20 : 100;

	/* Produce messages */
	test_produce_msgs_easy(topic, 0, partition, msgcnt);

	/* auto.offset.reset=latest: Consume messages from invalid offset:
	 * Should return EOF. */
	do_test_reset(topic, partition, "latest", msgcnt+5, 1, 0, 0, 0);
	
	/* auto.offset.reset=earliest: Consume messages from invalid offset:
	 * Should return messages from beginning. */
	do_test_reset(topic, partition, "earliest", msgcnt+5, 1, msgcnt, 0, 0);

	/* auto.offset.reset=error: Consume messages from invalid offset:
	 * Should return error. */
	do_test_reset(topic, partition, "error", msgcnt+5, 0, 0, 0, 1);

	return 0;
}


/**
 * @brief Verify auto.offset.reset=error behaviour for a range of different
 *        error cases.
 */
static void offset_reset_errors (void) {
        rd_kafka_t *c;
        rd_kafka_conf_t *conf;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        const char *topic = "topic";
        const int32_t partition = 0;
        const int msgcnt = 10;
        const int broker_id = 1;
        rd_kafka_queue_t *queue;
        int i;
        struct {
                rd_kafka_resp_err_t inject;
                rd_kafka_resp_err_t expect;
                /** Note: don't use OFFSET_BEGINNING since it might
                 *        use the cached low wmark, and thus not be subject to
                 *        the injected mock error. Use TAIL(msgcnt) instead.*/
                int64_t start_offset;
                int64_t expect_offset;
                rd_bool_t broker_down; /**< Bring the broker down */
        } test[] = {
                { RD_KAFKA_RESP_ERR__TRANSPORT,
                  RD_KAFKA_RESP_ERR_NO_ERROR,
                  RD_KAFKA_OFFSET_TAIL(msgcnt),
                  0,
                  .broker_down = rd_true,
                },
                { RD_KAFKA_RESP_ERR__TRANSPORT,
                  RD_KAFKA_RESP_ERR_NO_ERROR,
                  RD_KAFKA_OFFSET_TAIL(msgcnt),
                  0,
                  /* only disconnect on the ListOffsets request */
                  .broker_down = rd_false,
                },
                { RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED,
                  RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED,
                  RD_KAFKA_OFFSET_TAIL(msgcnt),
                  -1
                },
                { RD_KAFKA_RESP_ERR_NO_ERROR,
                  RD_KAFKA_RESP_ERR__NO_OFFSET,
                  RD_KAFKA_OFFSET_STORED, /* There's no committed offset */
                  -1
                },

        };

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(1, &bootstraps);

        /* Seed partition 0 with some messages so we can differ
         * between beginning and end. */
        test_produce_msgs_easy_v(topic, 0, partition, 0, msgcnt, 10,
                                 "security.protocol", "plaintext",
                                 "bootstrap.servers", bootstraps,
                                 NULL);

        test_conf_init(&conf, NULL, 60*5);

        test_conf_set(conf, "security.protocol", "plaintext");
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "enable.partition.eof", "true");
        test_conf_set(conf, "enable.auto.commit", "false");
        /* Speed up reconnects */
        test_conf_set(conf, "reconnect.backoff.max.ms", "1000");

        /* Raise an error (ERR__AUTO_OFFSET_RESET) so we can verify
         * if auto.offset.reset is triggered or not. */
        test_conf_set(conf, "auto.offset.reset", "error");

        rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_ERROR);

        c = test_create_consumer("mygroup", NULL, conf, NULL);

        queue = rd_kafka_queue_get_consumer(c);

        for (i = 0 ; i < (int)RD_ARRAYSIZE(test) ; i++) {
                rd_kafka_event_t *ev;
                rd_bool_t broker_down = rd_false;

                /* Make sure consumer is connected */
                test_wait_topic_exists(c, topic, 5000);

                TEST_SAY(_C_YEL "#%d: injecting %s, expecting %s\n",
                         i,
                         rd_kafka_err2name(test[i].inject),
                         rd_kafka_err2name(test[i].expect));

                if (test[i].broker_down) {
                        TEST_SAY("Bringing down the broker\n");
                        rd_kafka_mock_broker_set_down(mcluster, broker_id);
                        broker_down = rd_true;

                } else if (test[i].inject) {

                        rd_kafka_mock_push_request_errors(
                                mcluster,
                                RD_KAFKAP_ListOffsets, 5,
                                test[i].inject,
                                test[i].inject,
                                test[i].inject,
                                test[i].inject,
                                test[i].inject);

                        /* mock handler will close the connection on this
                         * request */
                        if (test[i].inject == RD_KAFKA_RESP_ERR__TRANSPORT)
                                broker_down = rd_true;

                }

                test_consumer_assign_partition("ASSIGN", c, topic, partition,
                                               test[i].start_offset);

                while (1) {
                        /* Poll until we see an AUTO_OFFSET_RESET error,
                         * timeout, or a message, depending on what we're
                         * looking for. */
                        ev = rd_kafka_queue_poll(queue, 5000);

                        if (!ev) {
                                TEST_ASSERT(broker_down,
                                            "#%d: poll timeout, but broker "
                                            "was not down",
                                            i);

                                /* Bring the broker back up and continue */
                                TEST_SAY("Bringing up the broker\n");
                                if (test[i].broker_down)
                                        rd_kafka_mock_broker_set_up(mcluster,
                                                                    broker_id);

                                broker_down = rd_false;

                        } else if (rd_kafka_event_type(ev) ==
                                   RD_KAFKA_EVENT_ERROR) {

                                if (rd_kafka_event_error(ev) !=
                                    RD_KAFKA_RESP_ERR__AUTO_OFFSET_RESET) {
                                        TEST_SAY("#%d: Ignoring %s event: %s\n",
                                                 i,
                                                 rd_kafka_event_name(ev),
                                                 rd_kafka_event_error_string(
                                                         ev));
                                        rd_kafka_event_destroy(ev);
                                        continue;
                                }

                                TEST_SAY("#%d: injected %s, got error %s: %s\n",
                                         i,
                                         rd_kafka_err2name(test[i].inject),
                                         rd_kafka_err2name(
                                                 rd_kafka_event_error(ev)),
                                         rd_kafka_event_error_string(ev));

                                /* The auto reset error code is always
                                 * ERR__AUTO_OFFSET_RESET, and the original
                                 * error is provided in the error string.
                                 * So use err2str() to compare the error
                                 * string to the expected error. */
                                TEST_ASSERT(
                                        strstr(rd_kafka_event_error_string(ev),
                                               rd_kafka_err2str(
                                                       test[i].expect)),
                                        "#%d: expected %s, got %s",
                                        i,
                                        rd_kafka_err2name(test[i].expect),
                                        rd_kafka_err2name(
                                                rd_kafka_event_error(ev)));

                                rd_kafka_event_destroy(ev);
                                break;

                        } else if (rd_kafka_event_type(ev) ==
                                   RD_KAFKA_EVENT_FETCH) {
                                const rd_kafka_message_t *rkm =
                                        rd_kafka_event_message_next(ev);

                                TEST_ASSERT(rkm, "#%d: got null message", i);

                                TEST_SAY("#%d: message at offset %"PRId64
                                         " (%s)\n",
                                         i,
                                         rkm->offset,
                                         rd_kafka_err2name(rkm->err));

                                TEST_ASSERT(!test[i].expect,
                                            "#%d: got message when expecting "
                                            "error", i);

                                TEST_ASSERT(test[i].expect_offset ==
                                            rkm->offset,
                                            "#%d: expected message offset "
                                            "%"PRId64", got %"PRId64
                                            " (%s)",
                                            i,
                                            test[i].expect_offset,
                                            rkm->offset,
                                            rd_kafka_err2name(rkm->err));

                                TEST_SAY("#%d: got expected message at "
                                         "offset %"PRId64" (%s)\n",
                                         i,
                                         rkm->offset,
                                         rd_kafka_err2name(rkm->err));

                                rd_kafka_event_destroy(ev);
                                break;

                        } else {
                                TEST_SAY("#%d: Ignoring %s event: %s\n",
                                         i,
                                         rd_kafka_event_name(ev),
                                         rd_kafka_event_error_string(ev));
                                rd_kafka_event_destroy(ev);
                        }
                }



                rd_kafka_mock_clear_request_errors(mcluster,
                                                   RD_KAFKAP_ListOffsets);
        }

        rd_kafka_queue_destroy(queue);

        rd_kafka_destroy(c);

        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

int main_0034_offset_reset_mock (int argc, char **argv) {
        offset_reset_errors();

        return 0;
}
