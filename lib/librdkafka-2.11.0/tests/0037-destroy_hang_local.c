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

#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


/**
 * Various regression tests for hangs on destroy.
 */



/**
 * Issue #530:
 * "Legacy Consumer. Delete hangs if done right after RdKafka::Consumer::create.
 *  But If I put a start and stop in between, there is no issue."
 */
static int legacy_consumer_early_destroy(void) {
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        int pass;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);

        for (pass = 0; pass < 2; pass++) {
                TEST_SAY("%s: pass #%d\n", __FUNCTION__, pass);

                rk = test_create_handle(RD_KAFKA_CONSUMER, NULL);

                if (pass == 1) {
                        /* Second pass, create a topic too. */
                        rkt = rd_kafka_topic_new(rk, topic, NULL);
                        TEST_ASSERT(rkt, "failed to create topic: %s",
                                    rd_kafka_err2str(rd_kafka_last_error()));
                        rd_sleep(1);
                        rd_kafka_topic_destroy(rkt);
                }

                rd_kafka_destroy(rk);
        }

        return 0;
}


int main_0037_destroy_hang_local(int argc, char **argv) {
        int fails = 0;

        test_conf_init(NULL, NULL, 30);

        fails += legacy_consumer_early_destroy();

        if (fails > 0)
                TEST_FAIL("See %d previous error(s)\n", fails);

        return 0;
}
