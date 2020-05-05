/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2013, Magnus Edenhill
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

/**
 * Tests event API.
 */


#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"  /* for Kafka driver */


static int msgid_next = 0;
static int fails = 0;

/**
 * Handle delivery reports
 */
static void handle_drs (rd_kafka_event_t *rkev) {
	const rd_kafka_message_t *rkmessage;

	while ((rkmessage = rd_kafka_event_message_next(rkev))) {
		int msgid = *(int *)rkmessage->_private;

		free(rkmessage->_private);

		TEST_SAYL(3,"Got rkmessage %s [%"PRId32"] @ %"PRId64": %s\n",
			  rd_kafka_topic_name(rkmessage->rkt),
			  rkmessage->partition, rkmessage->offset,
			  rd_kafka_err2str(rkmessage->err));
			 

		if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR)
			TEST_FAIL("Message delivery failed: %s\n",
				  rd_kafka_err2str(rkmessage->err));

		if (msgid != msgid_next) {
			fails++;
			TEST_FAIL("Delivered msg %i, expected %i\n",
				  msgid, msgid_next);
			return;
		}

		msgid_next = msgid+1;
	}
}


/**
 * @brief Test delivery report events
 */
int main_0039_event_dr (int argc, char **argv) {
	int partition = 0;
	int r;
	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *topic_conf;
	char msg[128];
	int msgcnt = test_quick ? 500 : 50000;
	int i;
        test_timing_t t_produce, t_delivery;
	rd_kafka_queue_t *eventq;

	test_conf_init(&conf, &topic_conf, 10);

	/* Set delivery report callback */
	rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

	rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_DR);

	/* Create kafka instance */
	rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

	eventq = rd_kafka_queue_get_main(rk);

	rkt = rd_kafka_topic_new(rk, test_mk_topic_name("0005", 0),
                                 topic_conf);
	if (!rkt)
		TEST_FAIL("Failed to create topic: %s\n",
			  rd_strerror(errno));

	/* Produce messages */
        TIMING_START(&t_produce, "PRODUCE");
	for (i = 0 ; i < msgcnt ; i++) {
		int *msgidp = malloc(sizeof(*msgidp));
		*msgidp = i;
		rd_snprintf(msg, sizeof(msg), "%s test message #%i", argv[0], i);
		r = rd_kafka_produce(rkt, partition, RD_KAFKA_MSG_F_COPY,
				     msg, strlen(msg), NULL, 0, msgidp);
		if (r == -1)
			TEST_FAIL("Failed to produce message #%i: %s\n",
				  i, rd_strerror(errno));
	}
        TIMING_STOP(&t_produce);
	TEST_SAY("Produced %i messages, waiting for deliveries\n", msgcnt);

	/* Wait for messages to be delivered */
        TIMING_START(&t_delivery, "DELIVERY");
	while (rd_kafka_outq_len(rk) > 0) {
		rd_kafka_event_t *rkev;
		rkev = rd_kafka_queue_poll(eventq, 1000);
		switch (rd_kafka_event_type(rkev))
		{
		case RD_KAFKA_EVENT_DR:
                        TEST_SAYL(3, "%s event with %zd messages\n",
                                  rd_kafka_event_name(rkev),
                                  rd_kafka_event_message_count(rkev));
			handle_drs(rkev);
			break;
		default:
			TEST_SAY("Unhandled event: %s\n",
				 rd_kafka_event_name(rkev));
			break;
		}
		rd_kafka_event_destroy(rkev);
	}
        TIMING_STOP(&t_delivery);

	if (fails)
		TEST_FAIL("%i failures, see previous errors", fails);

	if (msgid_next != msgcnt)
		TEST_FAIL("Still waiting for messages: next %i != end %i\n",
			  msgid_next, msgcnt);

	rd_kafka_queue_destroy(eventq);

	/* Destroy topic */
	rd_kafka_topic_destroy(rkt);

	/* Destroy rdkafka instance */
	TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
	rd_kafka_destroy(rk);

	return 0;
}



/**
 * @brief Local test: test event generation
 */
int main_0039_event (int argc, char **argv) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *eventq;
        int waitevent = 1;

        /* Set up a config with ERROR events enabled and
         * configure an invalid broker so that _TRANSPORT or ALL_BROKERS_DOWN
         * is promptly generated. */

        conf = rd_kafka_conf_new();

        rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_ERROR);
        rd_kafka_conf_set(conf, "bootstrap.servers", "0:65534", NULL, 0);

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        eventq = rd_kafka_queue_get_main(rk);

        while (waitevent) {
                rd_kafka_event_t *rkev;
                rkev = rd_kafka_queue_poll(eventq, 1000);
                switch (rd_kafka_event_type(rkev))
                {
                case RD_KAFKA_EVENT_ERROR:
                        TEST_SAY("Got %s%s event: %s: %s\n",
                                 rd_kafka_event_error_is_fatal(rkev) ?
                                 "FATAL " : "",
                                 rd_kafka_event_name(rkev),
                                 rd_kafka_err2name(rd_kafka_event_error(rkev)),
                                 rd_kafka_event_error_string(rkev));
                        waitevent = 0;
                        break;
                default:
                        TEST_SAY("Unhandled event: %s\n",
                                 rd_kafka_event_name(rkev));
                        break;
                }
                rd_kafka_event_destroy(rkev);
        }

        rd_kafka_queue_destroy(eventq);

        /* Destroy rdkafka instance */
        TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
        rd_kafka_destroy(rk);

        return 0;
}
