/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2025, Confluent Inc.
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
typedef struct consumer_s {
        const char *group_id;
        char *memberid;
} consumer_t;

static int
is_fatal_cb(rd_kafka_t *rk, rd_kafka_resp_err_t err, const char *reason) {
        if (err == RD_KAFKA_RESP_ERR__TIMED_OUT)
                return 0;
        return 1;
}

static int consumer_thread(void *arg) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *consumer;
        consumer_t *consumer_args = arg;

        test_curr->is_fatal_cb = is_fatal_cb;

        test_conf_init(&conf, NULL, 60);

        consumer =
            test_create_consumer(consumer_args->group_id, NULL, conf, NULL);

        consumer_args->memberid = rd_kafka_memberid(consumer);

        test_consumer_close(consumer);
        rd_kafka_destroy(consumer);
        test_curr->is_fatal_cb = NULL;
        return 0;
}

void do_test_unique_memberid() {
        int i;
        int j;
        int have_only_unique_memberids = 1;
        const char *group_id           = test_mk_topic_name("0153-memberid", 1);

#define CONSUMER_CNT 500
        thrd_t thread_id[CONSUMER_CNT];
        consumer_t consumer_args[CONSUMER_CNT];

        SUB_TEST_QUICK();

        for (i = 0; i < CONSUMER_CNT; i++) {
                consumer_args[i].group_id = group_id;
                consumer_args[i].memberid = NULL;
                thrd_create(&thread_id[i], consumer_thread, &consumer_args[i]);
        }

        for (i = 0; i < CONSUMER_CNT; i++) {
                thrd_join(thread_id[i], NULL);
        }

        for (i = 0; i < CONSUMER_CNT; i++) {
                if (have_only_unique_memberids) {
                        for (j = i + 1; j < CONSUMER_CNT; j++) {
                                if (strcmp(consumer_args[i].memberid,
                                           consumer_args[j].memberid) == 0) {
                                        TEST_SAY(
                                            "Consumer %d has the same member "
                                            "ID as consumer %d: %s\n",
                                            i, j, consumer_args[i].memberid);
                                        have_only_unique_memberids = 0;
                                        break;
                                }
                        }
                }
                rd_free(consumer_args[i].memberid);
        }

        if (have_only_unique_memberids) {
                TEST_SAY("All %d consumers have unique member IDs\n",
                         CONSUMER_CNT);
        } else {
                TEST_FAIL("Not all consumers have unique member IDs\n");
        }

        SUB_TEST_PASS();
}

int main_0153_memberid(int argc, char **argv) {

        if (test_consumer_group_protocol_classic()) {
                TEST_SKIP(
                    "Member ID is not generated on the client side in classic "
                    "protocol, skipping test");
                return 0;
        }

        if (!strcmp(test_mode, "valgrind")) {
                TEST_SKIP("Test is too heavy for valgrind, skipping it");
                return 0;
        }

        do_test_unique_memberid();

        return 0;
}
