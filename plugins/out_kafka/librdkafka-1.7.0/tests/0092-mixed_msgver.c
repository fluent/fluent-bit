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

#include "test.h"


/**
 * @name Mixed MsgVersions.
 *
 * - Create producer.
 * - Produce N/2 m essages. (with MsgVer2)
 * - Change the topic message.format.version to a MsgVer1 version.
 * - Consume the messages to verify all can be read.
 */



int main_0092_mixed_msgver (int argc, char **argv) {
        rd_kafka_t *rk;
        const char *topic = test_mk_topic_name("0092_mixed_msgver", 1);
        int32_t partition = 0;
        const int msgcnt = 60;
        int cnt;
        int64_t testid;
        int msgcounter = msgcnt;

        if (test_idempotent_producer) {
                TEST_SKIP("Idempotent producer requires MsgVersion >= 2\n");
                return 0;
        }

        testid = test_id_generate();

        rk = test_create_producer();

        /* Produce messages */
        for (cnt = 0 ; cnt < msgcnt ; cnt++) {
                rd_kafka_resp_err_t err;
                char buf[230];

                test_msg_fmt(buf, sizeof(buf), testid, partition, cnt);

                err = rd_kafka_producev(
                        rk,
                        RD_KAFKA_V_TOPIC(topic),
                        RD_KAFKA_V_PARTITION(partition),
                        RD_KAFKA_V_VALUE(buf, sizeof(buf)),
                        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                        RD_KAFKA_V_OPAQUE(&msgcounter),
                        RD_KAFKA_V_END);
                TEST_ASSERT(!err, "producev() #%d failed: %s",
                            cnt, rd_kafka_err2str(err));

                /* One message per batch */
                rd_kafka_flush(rk, 30*1000);

                if (cnt == msgcnt / 2) {
                        const char *msgconf[] = {
                                "message.format.version",
                                "0.10.0.0"
                        };
                        TEST_SAY("Changing message.format.version\n");
                        err = test_AlterConfigs_simple(
                                rk,
                                RD_KAFKA_RESOURCE_TOPIC, topic,
                                msgconf, 1);
                        TEST_ASSERT(!err,
                                    "AlterConfigs failed: %s",
                                    rd_kafka_err2str(err));
                }
        }

        rd_kafka_destroy(rk);

        /* Consume messages */
        test_consume_msgs_easy(NULL, topic, testid, -1, msgcnt, NULL);

        return 0;
}
