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
 * Tests "message.bytes.max"
 * Issue #24
 */

#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"  /* for Kafka driver */


static int msgs_wait = 0; /* bitmask */

/**
 * Delivery report callback.
 * Called for each message once to signal its delivery status.
 */
static void dr_cb (rd_kafka_t *rk, void *payload, size_t len,
                   rd_kafka_resp_err_t err, void *opaque, void *msg_opaque) {
        int msgid = *(int *)msg_opaque;

        free(msg_opaque);

        if (err)
                TEST_FAIL("Unexpected delivery error for message #%i: %s\n",
                          msgid, rd_kafka_err2str(err));

        if (!(msgs_wait & (1 << msgid)))
                TEST_FAIL("Unwanted delivery report for message #%i "
                          "(waiting for 0x%x)\n", msgid, msgs_wait);

        TEST_SAY("Delivery report for message #%i: %s\n",
                 msgid, rd_kafka_err2str(err));

        msgs_wait &= ~(1 << msgid);
}


int main_0003_msgmaxsize (int argc, char **argv) {
        int partition = 0;
        int r;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *topic_conf;
        char errstr[512];
        char *msg;
        static const int msgsize = 100000;
        int msgcnt = 10;
        int i;

        test_conf_init(&conf, &topic_conf, 10);

        /* Set a small maximum message size. */
        if (rd_kafka_conf_set(conf, "message.max.bytes", "100000",
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK)
                TEST_FAIL("%s\n", errstr);

        /* Set delivery report callback */
        rd_kafka_conf_set_dr_cb(conf, dr_cb);

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        rkt = rd_kafka_topic_new(rk, test_mk_topic_name("0003", 0),
                                 topic_conf);
        if (!rkt)
                TEST_FAIL("Failed to create topic: %s\n",
                          rd_strerror(errno));

        msg = calloc(1, msgsize);

        /* Produce 'msgcnt' messages, size odd ones larger than max.bytes,
         * and even ones smaller than max.bytes. */
        for (i = 0 ; i < msgcnt ; i++) {
                int *msgidp = malloc(sizeof(*msgidp));
                size_t len;
                int toobig = i & 1;

                *msgidp = i;
                if (toobig) {
                        /* Too big */
                        len = 200000;
                } else {
                        /* Good size */
                        len = 5000;
                        msgs_wait |= (1 << i);
                }

                rd_snprintf(msg, msgsize, "%s test message #%i", argv[0], i);
                r = rd_kafka_produce(rkt, partition, RD_KAFKA_MSG_F_COPY,
                                     msg, len, NULL, 0, msgidp);

                if (toobig) {
                        if (r != -1)
                                TEST_FAIL("Succeeded to produce too "
                                          "large message #%i\n", i);
                        free(msgidp);
                } else if (r == -1)
                        TEST_FAIL("Failed to produce message #%i: %s\n",
                                  i, rd_strerror(errno));
        }

        /* Wait for messages to be delivered. */
        while (rd_kafka_outq_len(rk) > 0)
                rd_kafka_poll(rk, 50);

        if (msgs_wait != 0)
                TEST_FAIL("Still waiting for messages: 0x%x\n", msgs_wait);

        free(msg);

        /* Destroy topic */
        rd_kafka_topic_destroy(rkt);

        /* Destroy rdkafka instance */
        TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
        rd_kafka_destroy(rk);

        return 0;
}
