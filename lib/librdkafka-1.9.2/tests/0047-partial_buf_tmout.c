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
#include "rdkafka.h"

#include <stdarg.h>

/**
 * Issue #756
 *
 * Partially sent buffers that timeout would cause the next request sent
 * to appear inside the partially sent buffer, eventually leading to an
 * InvalidReceiveException exception on the broker.
 *
 * This is easily triggered by:
 *  - decrease socket buffers
 *  - decrease message timeout
 *  - produce a bunch of large messages that will need to be partially sent
 *  - requests should timeout which should cause the connection to be closed
 *    by librdkafka.
 *
 * How do we monitor for correctness?
 *  - the broker shall not close the connection (but we might)
 */

static int got_timeout_err = 0;

static void
my_error_cb(rd_kafka_t *rk, int err, const char *reason, void *opaque) {
        got_timeout_err += (err == RD_KAFKA_RESP_ERR__TIMED_OUT);

        if (err == RD_KAFKA_RESP_ERR__TIMED_OUT ||
            err == RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN)
                TEST_SAY("Expected error: %s: %s\n", rd_kafka_err2str(err),
                         reason);
        else
                TEST_FAIL("Unexpected error: %s: %s", rd_kafka_err2str(err),
                          reason);
}

int main_0047_partial_buf_tmout(int argc, char **argv) {
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        rd_kafka_conf_t *conf;
        const size_t msg_size = 10000;
        int msgcounter        = 0;

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "socket.send.buffer.bytes", "1000");
        test_conf_set(conf, "batch.num.messages", "100");
        test_conf_set(conf, "queue.buffering.max.messages", "10000000");
        rd_kafka_conf_set_error_cb(conf, my_error_cb);
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        rkt = test_create_producer_topic(rk, topic, "message.timeout.ms", "300",
                                         NULL);

        while (got_timeout_err == 0) {
                test_produce_msgs_nowait(rk, rkt, 0, RD_KAFKA_PARTITION_UA, 0,
                                         10000, NULL, msg_size, 0, &msgcounter);
                rd_kafka_flush(rk, 100);
        }

        TEST_ASSERT(got_timeout_err > 0);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        return 0;
}
