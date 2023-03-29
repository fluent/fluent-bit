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

/**
 * Verify message timestamp behaviour on supporting brokers (>=0.10.0.0).
 * Issue #858
 */
struct timestamp_range {
        int64_t min;
        int64_t max;
};

static const struct timestamp_range invalid_timestamp = {-1, -1};
static struct timestamp_range broker_timestamp;
static struct timestamp_range my_timestamp;

static void prepare_timestamps(void) {
        struct timeval ts;
        rd_gettimeofday(&ts, NULL);

        /* broker timestamps expected to be within 600 seconds */
        broker_timestamp.min = (int64_t)ts.tv_sec * 1000LLU;
        broker_timestamp.max = broker_timestamp.min + (600 * 1000LLU);

        /* client timestamps: set in the future (24 hours)
         * to be outside of broker timestamps */
        my_timestamp.min = my_timestamp.max =
            (int64_t)ts.tv_sec + (24 * 3600 * 1000LLU);
}

/**
 * @brief Produce messages according to compress \p codec
 */
static void produce_msgs(const char *topic,
                         int partition,
                         uint64_t testid,
                         int msgcnt,
                         const char *broker_version,
                         const char *codec) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        int i;
        char key[128], buf[100];
        int msgcounter = msgcnt;

        test_conf_init(&conf, NULL, 0);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        test_conf_set(conf, "compression.codec", codec);
        test_conf_set(conf, "broker.version.fallback", broker_version);
        if (!strncmp(broker_version, "0.8", 3) ||
            !strncmp(broker_version, "0.9", 3)) {
                test_conf_set(conf, "api.version.request", "false");
                test_conf_set(conf, "enable.idempotence", "false");
        }

        /* Make sure to trigger a bunch of MessageSets */
        test_conf_set(conf, "batch.num.messages", tsprintf("%d", msgcnt / 5));
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        for (i = 0; i < msgcnt; i++) {
                rd_kafka_resp_err_t err;

                test_prepare_msg(testid, partition, i, buf, sizeof(buf), key,
                                 sizeof(key));

                err = rd_kafka_producev(
                    rk, RD_KAFKA_V_TOPIC(topic),
                    RD_KAFKA_V_VALUE(buf, sizeof(buf)),
                    RD_KAFKA_V_KEY(key, sizeof(key)),
                    RD_KAFKA_V_TIMESTAMP(my_timestamp.min),
                    RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                    RD_KAFKA_V_OPAQUE(&msgcounter), RD_KAFKA_V_END);
                if (err)
                        TEST_FAIL("producev() failed at msg #%d/%d: %s", i,
                                  msgcnt, rd_kafka_err2str(err));
        }

        TEST_SAY("Waiting for %d messages to be produced\n", msgcounter);
        while (msgcounter > 0)
                rd_kafka_poll(rk, 100);

        rd_kafka_destroy(rk);
}

static void
consume_msgs_verify_timestamps(const char *topic,
                               int partition,
                               uint64_t testid,
                               int msgcnt,
                               const struct timestamp_range *exp_timestamp) {
        test_msgver_t mv;

        test_msgver_init(&mv, testid);
        test_consume_msgs_easy_mv(topic, topic, -1, testid, -1, msgcnt, NULL,
                                  &mv);

        test_msgver_verify0(
            __FUNCTION__, __LINE__, topic, &mv,
            TEST_MSGVER_RANGE | TEST_MSGVER_BY_MSGID | TEST_MSGVER_BY_TIMESTAMP,
            (struct test_mv_vs) {.msg_base      = 0,
                                 .exp_cnt       = msgcnt,
                                 .timestamp_min = exp_timestamp->min,
                                 .timestamp_max = exp_timestamp->max});

        test_msgver_clear(&mv);
}



static void test_timestamps(const char *broker_tstype,
                            const char *broker_version,
                            const char *codec,
                            const struct timestamp_range *exp_timestamps) {
        const char *topic =
            test_mk_topic_name(tsprintf("0052_msg_timestamps_%s_%s_%s",
                                        broker_tstype, broker_version, codec),
                               1);
        const int msgcnt = 20;
        uint64_t testid  = test_id_generate();

        if ((!strncmp(broker_version, "0.9", 3) ||
             !strncmp(broker_version, "0.8", 3)) &&
            !test_conf_match(NULL, "sasl.mechanisms", "GSSAPI")) {
                TEST_SAY(_C_YEL
                         "Skipping %s, %s test: "
                         "SaslHandshake not supported by broker v%s" _C_CLR
                         "\n",
                         broker_tstype, codec, broker_version);
                return;
        }

        TEST_SAY(_C_MAG "Timestamp test using %s\n", topic);
        test_timeout_set(30);

        test_kafka_topics(
            "--create --topic \"%s\" "
            "--replication-factor 1 --partitions 1 "
            "--config message.timestamp.type=%s",
            topic, broker_tstype);

        TEST_SAY(_C_MAG "Producing %d messages to %s\n", msgcnt, topic);
        produce_msgs(topic, 0, testid, msgcnt, broker_version, codec);

        TEST_SAY(_C_MAG
                 "Consuming and verifying %d messages from %s "
                 "with expected timestamps %" PRId64 "..%" PRId64 "\n",
                 msgcnt, topic, exp_timestamps->min, exp_timestamps->max);

        consume_msgs_verify_timestamps(topic, 0, testid, msgcnt,
                                       exp_timestamps);
}


int main_0052_msg_timestamps(int argc, char **argv) {

        if (!test_can_create_topics(1))
                return 0;

        /* Broker version limits the producer's feature set,
         * for 0.9.0.0 no timestamp will be transmitted,
         * but for 0.10.1.0 (or newer, api.version.request will be true)
         * the producer will set the timestamp.
         * In all cases we want a reasonable timestamp back.
         *
         * Explicit broker LogAppendTime setting will overwrite
         * any producer-provided offset.
         *
         * Using the old non-timestamp-aware protocol without
         * LogAppendTime will cause unset/invalid timestamps .
         *
         * Any other option should honour the producer create timestamps.
         */
        prepare_timestamps();

        test_timestamps("CreateTime", "0.10.1.0", "none", &my_timestamp);
        test_timestamps("LogAppendTime", "0.10.1.0", "none", &broker_timestamp);
        test_timestamps("CreateTime", "0.9.0.0", "none", &invalid_timestamp);
        test_timestamps("LogAppendTime", "0.9.0.0", "none", &broker_timestamp);
#if WITH_ZLIB
        test_timestamps("CreateTime", "0.10.1.0", "gzip", &my_timestamp);
        test_timestamps("LogAppendTime", "0.10.1.0", "gzip", &broker_timestamp);
        test_timestamps("CreateTime", "0.9.0.0", "gzip", &invalid_timestamp);
        test_timestamps("LogAppendTime", "0.9.0.0", "gzip", &broker_timestamp);
#endif

        return 0;
}
