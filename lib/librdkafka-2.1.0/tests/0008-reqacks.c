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
 * Tests request.required.acks (issue #75)
 */


#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


static int msgid_next = 0;
static int fails      = 0;
static rd_kafka_msg_status_t exp_status;

/**
 * Delivery reported callback.
 * Called for each message once to signal its delivery status.
 */
static void
dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
        int msgid                    = *(int *)rkmessage->_private;
        rd_kafka_msg_status_t status = rd_kafka_message_status(rkmessage);

        free(rkmessage->_private);

        if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR)
                TEST_FAIL("Message delivery failed: %s (status %d)\n",
                          rd_kafka_err2str(rkmessage->err), status);

        if (msgid != msgid_next) {
                fails++;
                TEST_FAIL("Delivered msg %i, expected %i\n", msgid, msgid_next);
                return;
        }

        TEST_ASSERT(status == exp_status,
                    "For msgid #%d: expected status %d, got %d", msgid,
                    exp_status, status);

        msgid_next = msgid + 1;
}


int main_0008_reqacks(int argc, char **argv) {
        int partition = 0;
        int r;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *topic_conf;
        char errstr[512];
        char msg[128];
        int msgcnt = test_quick ? 20 : 100;
        int i;
        int reqacks;
        int idbase        = 0;
        const char *topic = NULL;

        TEST_SAY(
            "\033[33mNOTE! This test requires at "
            "least 3 brokers!\033[0m\n");

        TEST_SAY(
            "\033[33mNOTE! This test requires "
            "default.replication.factor=3 to be configured on "
            "all brokers!\033[0m\n");

        /* Try different request.required.acks settings (issue #75) */
        for (reqacks = -1; reqacks <= 1; reqacks++) {
                char tmp[10];

                test_conf_init(&conf, &topic_conf, 10);

                if (reqacks != -1)
                        test_conf_set(conf, "enable.idempotence", "false");

                if (!topic)
                        topic = test_mk_topic_name("0008", 0);

                rd_snprintf(tmp, sizeof(tmp), "%i", reqacks);

                if (rd_kafka_topic_conf_set(topic_conf, "request.required.acks",
                                            tmp, errstr,
                                            sizeof(errstr)) != RD_KAFKA_CONF_OK)
                        TEST_FAIL("%s", errstr);

                /* Set delivery report callback */
                rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

                if (reqacks == 0)
                        exp_status = RD_KAFKA_MSG_STATUS_POSSIBLY_PERSISTED;
                else
                        exp_status = RD_KAFKA_MSG_STATUS_PERSISTED;

                /* Create kafka instance */
                rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

                TEST_SAY(
                    "Created    kafka instance %s with required acks %d, "
                    "expecting status %d\n",
                    rd_kafka_name(rk), reqacks, exp_status);

                rkt = rd_kafka_topic_new(rk, topic, topic_conf);
                if (!rkt)
                        TEST_FAIL("Failed to create topic: %s\n",
                                  rd_strerror(errno));

                /* Produce messages */
                for (i = 0; i < msgcnt; i++) {
                        int *msgidp = malloc(sizeof(*msgidp));
                        *msgidp     = idbase + i;
                        rd_snprintf(msg, sizeof(msg),
                                    "%s test message #%i (acks=%i)", argv[0],
                                    *msgidp, reqacks);
                        r = rd_kafka_produce(rkt, partition,
                                             RD_KAFKA_MSG_F_COPY, msg,
                                             strlen(msg), NULL, 0, msgidp);
                        if (r == -1)
                                TEST_FAIL("Failed to produce message #%i: %s\n",
                                          *msgidp, rd_strerror(errno));
                }

                TEST_SAY("Produced %i messages, waiting for deliveries\n",
                         msgcnt);

                /* Wait for messages to time out */
                while (rd_kafka_outq_len(rk) > 0)
                        rd_kafka_poll(rk, 50);

                if (fails)
                        TEST_FAIL("%i failures, see previous errors", fails);

                if (msgid_next != idbase + msgcnt)
                        TEST_FAIL(
                            "Still waiting for messages: "
                            "next %i != end %i\n",
                            msgid_next, msgcnt);
                idbase += i;

                /* Destroy topic */
                rd_kafka_topic_destroy(rkt);

                /* Destroy rdkafka instance */
                TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
                rd_kafka_destroy(rk);
        }

        return 0;
}
