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

        static const struct {
                ssize_t keylen;
                ssize_t len;
                rd_kafka_resp_err_t exp_err;
        } sizes[] = {
                /* message.max.bytes is including framing */
                { -1, 5000, RD_KAFKA_RESP_ERR_NO_ERROR },
                { 0, 99900, RD_KAFKA_RESP_ERR_NO_ERROR },
                { 0, 100000, RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE },
                { 100000, 0, RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE },
                { 1000, 100000, RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE },
                { 0, 101000, RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE },
                { 99000, -1, RD_KAFKA_RESP_ERR_NO_ERROR },
                { -1, -1, RD_KAFKA_RESP_ERR__END }
        };
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

        for (i = 0 ; sizes[i].exp_err != RD_KAFKA_RESP_ERR__END ; i++) {
                void *value = sizes[i].len != -1 ?
                        calloc(1, sizes[i].len) : NULL;
                size_t len = sizes[i].len != -1 ? sizes[i].len : 0;
                void *key = sizes[i].keylen != -1 ?
                        calloc(1, sizes[i].keylen) : NULL;
                size_t keylen = sizes[i].keylen != -1 ? sizes[i].keylen : 0;
                int *msgidp = malloc(sizeof(*msgidp));
                rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;

                *msgidp = i;

                r = rd_kafka_produce(rkt, partition, RD_KAFKA_MSG_F_COPY,
                                     value, len,
                                     key, keylen,
                                     msgidp);
                if (r == -1)
                        err = rd_kafka_last_error();

                if (err != sizes[i].exp_err) {
                        TEST_FAIL("Msg #%d produce(len=%"PRIdsz
                                  ", keylen=%"PRIdsz"): got %s, expected %s",
                                  i,
                                  sizes[i].len,
                                  sizes[i].keylen,
                                  rd_kafka_err2name(err),
                                  rd_kafka_err2name(sizes[i].exp_err));
                } else {
                        TEST_SAY("Msg #%d produce() returned expected %s "
                                 "for value size %"PRIdsz
                                 " and key size %"PRIdsz"\n",
                                 i,
                                 rd_kafka_err2name(err),
                                 sizes[i].len,
                                 sizes[i].keylen);

                        if (!sizes[i].exp_err)
                                msgs_wait |= (1 << i);
                        else
                                free(msgidp);
                }
        }

        /* Wait for messages to be delivered. */
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
