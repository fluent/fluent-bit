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
 * Issue #345, #821
 * Test that topic_new() + topic_destroy() can be used as a topic-lookup cache,
 * i.e., as long as the app topic refcount stays above 1 the app can call
 * new() and destroy() any number of times (symetrically).
 */


int main_0046_rkt_cache(int argc, char **argv) {
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        int i;

        rk = test_create_producer();

        rkt = test_create_producer_topic(rk, topic, NULL);

        for (i = 0; i < 100; i++) {
                rd_kafka_topic_t *rkt2;

                rkt2 = rd_kafka_topic_new(rk, topic, NULL);
                TEST_ASSERT(rkt2 != NULL);

                rd_kafka_topic_destroy(rkt2);
        }

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        return 0;
}
