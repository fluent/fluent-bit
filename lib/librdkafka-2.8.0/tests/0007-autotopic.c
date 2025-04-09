/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
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
 * Auto create topics
 *
 * NOTE! This test requires auto.create.topics.enable=true to be
 *       configured on the broker!
 */


#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


static int msgs_wait = 0; /* bitmask */

/**
 * Delivery report callback.
 * Called for each message once to signal its delivery status.
 */
static void dr_cb(rd_kafka_t *rk,
                  void *payload,
                  size_t len,
                  rd_kafka_resp_err_t err,
                  void *opaque,
                  void *msg_opaque) {
        int msgid = *(int *)msg_opaque;

        free(msg_opaque);

        if (!(msgs_wait & (1 << msgid)))
                TEST_FAIL(
                    "Unwanted delivery report for message #%i "
                    "(waiting for 0x%x)\n",
                    msgid, msgs_wait);

        TEST_SAY("Delivery report for message #%i: %s\n", msgid,
                 rd_kafka_err2str(err));

        msgs_wait &= ~(1 << msgid);

        if (err)
                TEST_FAIL("Message #%i failed with unexpected error %s\n",
                          msgid, rd_kafka_err2str(err));
}


int main_0007_autotopic(int argc, char **argv) {
        int partition = 0;
        int r;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *topic_conf;
        char msg[128];
        int msgcnt = 10;
        int i;

        /* Generate unique topic name */
        test_conf_init(&conf, &topic_conf, 10);

        TEST_SAY(
            "\033[33mNOTE! This test requires "
            "auto.create.topics.enable=true to be configured on "
            "the broker!\033[0m\n");

        /* Set delivery report callback */
        rd_kafka_conf_set_dr_cb(conf, dr_cb);

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        rkt = rd_kafka_topic_new(rk, test_mk_topic_name("0007_autotopic", 1),
                                 topic_conf);
        if (!rkt)
                TEST_FAIL("Failed to create topic: %s\n", rd_strerror(errno));

        /* Produce a message */
        for (i = 0; i < msgcnt; i++) {
                int *msgidp = malloc(sizeof(*msgidp));
                *msgidp     = i;
                rd_snprintf(msg, sizeof(msg), "%s test message #%i", argv[0],
                            i);
                r = rd_kafka_produce(rkt, partition, RD_KAFKA_MSG_F_COPY, msg,
                                     strlen(msg), NULL, 0, msgidp);
                if (r == -1)
                        TEST_FAIL("Failed to produce message #%i: %s\n", i,
                                  rd_strerror(errno));
                msgs_wait |= (1 << i);
        }

        /* Wait for messages to time out */
        while (rd_kafka_outq_len(rk) > 0)
                rd_kafka_poll(rk, 50);

        if (msgs_wait != 0)
                TEST_FAIL("Still waiting for messages: 0x%x\n", msgs_wait);

        /* Destroy topic */
        rd_kafka_topic_destroy(rkt);

        /* Destroy rdkafka instance */
        TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
        rd_kafka_destroy(rk);

        return 0;
}
