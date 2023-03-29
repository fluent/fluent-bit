/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2018, Magnus Edenhill
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
 * Tests the queue callback IO event signalling.
 */


#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


/**
 * @brief Thread safe event counter */
static struct {
        mtx_t lock;
        int count;
} event_receiver;

/**
 * @brief Event callback function. Check the opaque pointer and
 *        increase the count of received event. */
static void event_cb(rd_kafka_t *rk_p, void *opaque) {
        TEST_ASSERT(opaque == (void *)0x1234,
                    "Opaque pointer is not as expected (got: %p)", opaque);
        mtx_lock(&event_receiver.lock);
        event_receiver.count += 1;
        mtx_unlock(&event_receiver.lock);
}

/**
 * @brief Wait for one or more events to be received.
 *        Return 0 if no event was received within the timeout. */
static int wait_event_cb(int timeout_secs) {
        int event_count = 0;
        for (; timeout_secs >= 0; timeout_secs--) {
                mtx_lock(&event_receiver.lock);
                event_count          = event_receiver.count;
                event_receiver.count = 0;
                mtx_unlock(&event_receiver.lock);
                if (event_count > 0 || timeout_secs == 0)
                        return event_count;
                rd_sleep(1);
        }
        return 0;
}


int main_0083_cb_event(int argc, char **argv) {
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *tconf;
        rd_kafka_t *rk_p, *rk_c;
        const char *topic;
        rd_kafka_topic_t *rkt_p;
        rd_kafka_queue_t *queue;
        uint64_t testid;
        int msgcnt          = 100;
        int recvd           = 0;
        int wait_multiplier = 1;
        rd_kafka_resp_err_t err;
        enum { _NOPE, _YEP, _REBALANCE } expecting_io = _REBALANCE;
        int callback_event_count;
        rd_kafka_event_t *rkev;
        int eventcnt = 0;

        mtx_init(&event_receiver.lock, mtx_plain);

        testid = test_id_generate();
        topic  = test_mk_topic_name(__FUNCTION__, 1);

        rk_p  = test_create_producer();
        rkt_p = test_create_producer_topic(rk_p, topic, NULL);
        err   = test_auto_create_topic_rkt(rk_p, rkt_p, tmout_multip(5000));
        TEST_ASSERT(!err, "Topic auto creation failed: %s",
                    rd_kafka_err2str(err));

        test_conf_init(&conf, &tconf, 0);
        rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_REBALANCE);
        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "enable.partition.eof", "false");
        /* Speed up propagation of new topics */
        test_conf_set(conf, "metadata.max.age.ms", "5000");
        test_topic_conf_set(tconf, "auto.offset.reset", "earliest");
        rk_c = test_create_consumer(topic, NULL, conf, tconf);

        queue = rd_kafka_queue_get_consumer(rk_c);

        test_consumer_subscribe(rk_c, topic);

        rd_kafka_queue_cb_event_enable(queue, event_cb, (void *)0x1234);

        /**
         * 1) Wait for rebalance event
         * 2) Wait 1 interval (1s) expecting no IO (nothing produced).
         * 3) Produce half the messages
         * 4) Expect CB
         * 5) Consume the available messages
         * 6) Wait 1 interval expecting no CB.
         * 7) Produce remaing half
         * 8) Expect CB
         * 9) Done.
         */
        while (recvd < msgcnt) {
                TEST_SAY("Waiting for event\n");
                callback_event_count = wait_event_cb(1 * wait_multiplier);
                TEST_ASSERT(callback_event_count <= 1,
                            "Event cb called %d times", callback_event_count);

                if (callback_event_count == 1) {
                        TEST_SAY("Events received: %d\n", callback_event_count);

                        while ((rkev = rd_kafka_queue_poll(queue, 0))) {
                                eventcnt++;
                                switch (rd_kafka_event_type(rkev)) {
                                case RD_KAFKA_EVENT_REBALANCE:
                                        TEST_SAY(
                                            "Got %s: %s\n",
                                            rd_kafka_event_name(rkev),
                                            rd_kafka_err2str(
                                                rd_kafka_event_error(rkev)));
                                        if (expecting_io != _REBALANCE)
                                                TEST_FAIL(
                                                    "Got Rebalance when "
                                                    "expecting message\n");
                                        if (rd_kafka_event_error(rkev) ==
                                            RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS) {
                                                rd_kafka_assign(
                                                    rk_c,
                                                    rd_kafka_event_topic_partition_list(
                                                        rkev));
                                                expecting_io = _NOPE;
                                        } else
                                                rd_kafka_assign(rk_c, NULL);
                                        break;

                                case RD_KAFKA_EVENT_FETCH:
                                        if (expecting_io != _YEP)
                                                TEST_FAIL(
                                                    "Did not expect more "
                                                    "messages at %d/%d\n",
                                                    recvd, msgcnt);
                                        recvd++;
                                        if (recvd == (msgcnt / 2) ||
                                            recvd == msgcnt)
                                                expecting_io = _NOPE;
                                        break;

                                case RD_KAFKA_EVENT_ERROR:
                                        TEST_FAIL(
                                            "Error: %s\n",
                                            rd_kafka_event_error_string(rkev));
                                        break;

                                default:
                                        TEST_SAY("Ignoring event %s\n",
                                                 rd_kafka_event_name(rkev));
                                }

                                rd_kafka_event_destroy(rkev);
                        }
                        TEST_SAY("%d events, Consumed %d/%d messages\n",
                                 eventcnt, recvd, msgcnt);

                        wait_multiplier = 1;

                } else {
                        if (expecting_io == _REBALANCE) {
                                continue;
                        } else if (expecting_io == _YEP) {
                                TEST_FAIL(
                                    "Did not see expected IO after %d/%d "
                                    "msgs\n",
                                    recvd, msgcnt);
                        }

                        TEST_SAY("Event wait timeout (good)\n");
                        TEST_SAY("Got idle period, producing\n");
                        test_produce_msgs(rk_p, rkt_p, testid, 0, recvd,
                                          msgcnt / 2, NULL, 10);

                        expecting_io = _YEP;
                        /* When running slowly (e.g., valgrind) it might take
                         * some time before the first message is received
                         * after producing. */
                        wait_multiplier = 3;
                }
        }
        TEST_SAY("Done\n");

        rd_kafka_topic_destroy(rkt_p);
        rd_kafka_destroy(rk_p);

        rd_kafka_queue_destroy(queue);
        rd_kafka_consumer_close(rk_c);
        rd_kafka_destroy(rk_c);

        mtx_destroy(&event_receiver.lock);

        return 0;
}
