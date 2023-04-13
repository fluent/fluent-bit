/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2021, Magnus Edenhill
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


/**
 * @brief Verify that a FetchResponse containing only aborted messages does not
 *        raise a ERR_MSG_SIZE_TOO_LARGE error. #2993.
 *
 * 1. Create topic with a small message.max.bytes to make sure that
 *    there's at least one full fetch response without any control messages,
 *    just aborted messages.
 * 2. Transactionally produce 10x the message.max.bytes.
 * 3. Abort the transaction.
 * 4. Consume from start, verify that no error is received, wait for EOF.
 *
 */
int main_0129_fetch_aborted_msgs(int argc, char **argv) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        const char *topic    = test_mk_topic_name("0129_fetch_aborted_msgs", 1);
        const int msgcnt     = 1000;
        const size_t msgsize = 1000;

        test_conf_init(&conf, NULL, 30);

        test_conf_set(conf, "linger.ms", "10000");
        test_conf_set(conf, "transactional.id", topic);
        test_conf_set(conf, "message.max.bytes", "10000");
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        test_admin_create_topic(rk, topic, 1, 1,
                                (const char *[]) {"max.message.bytes", "10000",
                                                  "segment.bytes", "20000",
                                                  NULL});

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        /* Produce half set of messages without waiting for delivery. */
        test_produce_msgs2(rk, topic, 0, 0, 0, msgcnt, NULL, msgsize);

        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));

        rd_kafka_destroy(rk);

        /* Verify messages were actually produced by consuming them back. */
        test_consume_msgs_easy(topic, topic, 0, 1, 0, NULL);

        return 0;
}
