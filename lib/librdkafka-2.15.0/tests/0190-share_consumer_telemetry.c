/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2026, Confluent Inc.
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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define TELEMETRY_TOPIC_DEFAULT "client-telemetry-metrics"
#define METRIC_PREFIX           "org.apache.kafka."

/* Expected share-consumer metric suffixes (without the org.apache.kafka.
 * prefix). Mirrors RD_KAFKA_TELEMETRY_SHARE_CONSUMER_METRICS_INFO in
 * src/rdkafka_telemetry_encode.h; hardcoded here so the test doesn't
 * transitively include the internal header. */
static const char *const EXPECTED_SHARE_CONSUMER_METRICS[] = {
    "consumer.share.poll.idle.ratio.avg",
    "consumer.share.time.between.poll.avg",
    "consumer.share.time.between.poll.max",
    "consumer.share.fetch.manager.fetch.total",
    "consumer.share.fetch.manager.fetch.rate",
    "consumer.share.fetch.manager.fetch.latency.avg",
    "consumer.share.fetch.manager.fetch.latency.max",
    "consumer.share.fetch.manager.acknowledgements.send.total",
    "consumer.share.fetch.manager.acknowledgements.send.rate",
    "consumer.share.fetch.manager.fetch.throttle.time.avg",
    "consumer.share.fetch.manager.fetch.throttle.time.max",
    "consumer.share.coordinator.heartbeat.total",
    "consumer.share.coordinator.heartbeat.rate",
    "consumer.share.fetch.manager.fetch.size.avg",
    "consumer.share.fetch.manager.fetch.size.max",
    "consumer.share.fetch.manager.bytes.consumed.total",
    "consumer.share.fetch.manager.bytes.consumed.rate",
};

#define EXPECTED_SHARE_CONSUMER_METRICS_CNT                                    \
        (sizeof(EXPECTED_SHARE_CONSUMER_METRICS) /                             \
         sizeof(EXPECTED_SHARE_CONSUMER_METRICS[0]))

static const char *telemetry_topic(void) {
        const char *env = getenv("TELEMETRY_TOPIC");
        return env && *env ? env : TELEMETRY_TOPIC_DEFAULT;
}

/* Fixed-capacity set of unique metric names. */
#define MAX_SEEN_METRICS    64
#define MAX_METRIC_NAME_LEN 256

typedef struct {
        char names[MAX_SEEN_METRICS][MAX_METRIC_NAME_LEN];
        int cnt;
} seen_metrics_t;

static rd_bool_t seen_metrics_contains(const seen_metrics_t *seen,
                                       const char *name) {
        int i;
        for (i = 0; i < seen->cnt; i++) {
                if (strcmp(seen->names[i], name) == 0)
                        return rd_true;
        }
        return rd_false;
}

static void seen_metrics_add(seen_metrics_t *seen, const char *name) {
        if (seen_metrics_contains(seen, name))
                return;
        if (seen->cnt >= MAX_SEEN_METRICS) {
                TEST_FAIL(
                    "seen_metrics capacity (%d) exceeded; dropping '%s'\n",
                    MAX_SEEN_METRICS, name);
                return;
        }
        rd_snprintf(seen->names[seen->cnt], MAX_METRIC_NAME_LEN, "%s", name);
        seen->cnt++;
}

/**
 * @name End-to-end share-consumer telemetry integration test.
 *
 * Requires external infrastructure already brought up by the surrounding
 * pipeline (packaging/tools/setup-share-telemetry-testing.sh):
 *   - broker with ClientOtlpMetricsReporter plugin loaded
 *   - OpenTelemetry Collector with Kafka exporter
 *   - topic "client-telemetry-metrics" (the OTel-exported telemetry sink)
 *   - client metrics subscription on "org.apache.kafka.consumer.share." prefix
 */

/**
 * @brief Scan a raw byte buffer for every
 *        "org.apache.kafka.consumer.share.<chars>" substring and add each
 *        unique one to the names list.
 *
 * The OTLP protobuf encoding leaves metric names as plain UTF-8 — the
 * field tag is binary but the string payload is uncompressed.
 */
static void
extract_share_metric_names(const void *data, size_t len, seen_metrics_t *seen) {
        const char *p           = (const char *)data;
        const char *end         = p + len;
        const char prefix[]     = METRIC_PREFIX "consumer.share.";
        const size_t prefix_len = sizeof(prefix) - 1;

        while (p + prefix_len <= end) {
                const char *match = NULL;
                const char *q;
                for (q = p; q + prefix_len <= end; q++) {
                        if (memcmp(q, prefix, prefix_len) == 0) {
                                match = q;
                                break;
                        }
                }
                if (!match)
                        break;

                const char *name_end = match + prefix_len;
                while (name_end < end &&
                       (isalnum((unsigned char)*name_end) || *name_end == '.' ||
                        *name_end == '_')) {
                        name_end++;
                }

                size_t name_len = (size_t)(name_end - match);
                if (name_len > 0 && name_len < MAX_METRIC_NAME_LEN) {
                        char name[MAX_METRIC_NAME_LEN];
                        memcpy(name, match, name_len);
                        name[name_len] = '\0';
                        seen_metrics_add(seen, name);
                }

                p = name_end;
        }
}

/**
 * @brief Produce a batch of messages and drive a share consumer through
 *        the consume path so the telemetry sampling sites fire.
 */
static void produce_and_share_consume(const char *topic, const char *group_id) {
        rd_kafka_share_t *rkshare;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_resp_err_t err;
        char errstr[512];
        int64_t deadline_us;
        int consumed = 0;

        TEST_SAY("Producing %d messages to %s\n", 200, topic);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 30 * 1000);
        test_produce_msgs_easy(topic, 0, RD_KAFKA_PARTITION_UA, 200);

        TEST_SAY(
            "Starting share consumer (enable.metrics.push=true) for %d s\n",
            20);

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "group.id", group_id);
        test_conf_set(conf, "enable.metrics.push", "true");

        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(rkshare, "share_consumer_new failed: %s", errstr);

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        err = rd_kafka_share_subscribe(rkshare, subs);
        rd_kafka_topic_partition_list_destroy(subs);
        TEST_ASSERT(!err, "share_subscribe: %s", rd_kafka_err2str(err));

        deadline_us = test_clock() + 20 * 1000000;
        while (test_clock() < deadline_us) {
                rd_kafka_messages_t *batch = NULL;
                rd_kafka_error_t *e;
                size_t rcvd = 0;
                size_t i;

                e = rd_kafka_share_poll(rkshare, 1000, &batch);
                if (e) {
                        rd_kafka_error_destroy(e);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (i = 0; i < rcvd; i++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, i);
                        if (msg && !msg->err)
                                consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_SAY("Share-consumed %d messages\n", consumed);

        rd_kafka_share_consumer_close(rkshare);
        rd_kafka_share_destroy(rkshare);
}

/**
 * @brief Open a regular consumer on the telemetry topic, drain it for
 *        up to the given number of seconds, returning a list of every
 *        distinct "consumer.share.*" metric name seen across all messages.
 */
static void
consume_telemetry_topic(const char *topic, int seconds, seen_metrics_t *seen) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_partition_list_t *subs;
        int64_t deadline_us;
        int msgs_seen = 0;

        TEST_SAY("Consuming '%s' for up to %d s\n", topic, seconds);

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "group.id", "0190-telemetry-verifier");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");

        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);
        rd_kafka_poll_set_consumer(rk);

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        rd_kafka_subscribe(rk, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        deadline_us = test_clock() + (int64_t)seconds * 1000000;
        while (test_clock() < deadline_us) {
                rd_kafka_message_t *msg = rd_kafka_consumer_poll(rk, 1000);
                if (!msg)
                        continue;
                if (msg->err) {
                        rd_kafka_message_destroy(msg);
                        continue;
                }
                msgs_seen++;
                extract_share_metric_names(msg->payload, msg->len, seen);
                rd_kafka_message_destroy(msg);
        }

        TEST_SAY(
            "Read %d telemetry messages, observed %d distinct share metric "
            "names\n",
            msgs_seen, seen->cnt);

        rd_kafka_consumer_close(rk);
        rd_kafka_destroy(rk);
}

/**
 * @brief Compare the seen-names list against EXPECTED_METRICS and
 *        TEST_ASSERT that every expected name appears with the full
 *        "org.apache.kafka." prefix.
 */
static void verify_metrics(const seen_metrics_t *seen) {
        int missing      = 0;
        int expected_cnt = 0;
        size_t i;

        TEST_SAY("Verifying expected share-consumer metric names:\n");
        for (i = 0; i < EXPECTED_SHARE_CONSUMER_METRICS_CNT; i++) {
                char full_name[MAX_METRIC_NAME_LEN];
                const char *short_name = EXPECTED_SHARE_CONSUMER_METRICS[i];
                int found;

                rd_snprintf(full_name, sizeof(full_name), METRIC_PREFIX "%s",
                            short_name);
                found = seen_metrics_contains(seen, full_name) ? 1 : 0;
                expected_cnt++;
                TEST_SAY("  %s  %s\n", found ? "[OK]" : "[MISSING]", full_name);
                if (!found)
                        missing++;
        }

        TEST_ASSERT(missing == 0,
                    "%d of %d expected share-consumer metric name(s) "
                    "were not observed in topic '%s'",
                    missing, expected_cnt, telemetry_topic());

        TEST_SAY("PASS: all %d expected share-consumer metric names observed\n",
                 expected_cnt);
}


/**
 * @brief Return 1 if the given topic exists on the broker, 0 otherwise.
 *
 * Used to decide whether the surrounding telemetry pipeline is set up.
 * If the OTel Collector is not running and producing into the topic,
 * the topic itself won't exist and the test is skipped. CI pipelines
 * that intend to exercise the full path are expected to verify infra
 * health themselves before invoking this test.
 */
static int telemetry_infra_available(const char *topic) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        const struct rd_kafka_metadata *md;
        rd_kafka_resp_err_t err;
        int found = 0;
        int i;

        test_conf_init(&conf, NULL, 30);
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        /* List ALL topics — does NOT trigger broker-side auto-create the
         * way a per-topic metadata query would on clusters that have
         * auto.create.topics.enable=true (e.g. trivup). */
        err = rd_kafka_metadata(rk, 1, NULL, &md, 10 * 1000);
        if (err == RD_KAFKA_RESP_ERR_NO_ERROR) {
                for (i = 0; i < md->topic_cnt; i++) {
                        if (strcmp(md->topics[i].topic, topic) == 0 &&
                            md->topics[i].err == RD_KAFKA_RESP_ERR_NO_ERROR &&
                            md->topics[i].partition_cnt > 0) {
                                found = 1;
                                break;
                        }
                }
                rd_kafka_metadata_destroy(md);
        }

        rd_kafka_destroy(rk);
        return found;
}

/**
 * @brief Sub-test: basic produce → share-consume → verify metrics flow.
 *
 * Produces a batch of messages to a fresh topic, drives a share consumer
 * over them so the telemetry sampling sites fire, then consumes from the
 * telemetry topic and asserts every expected share-consumer metric name
 * appears at least once.
 */
static void do_test_produce_share_consume_verify_metrics(void) {
        const char *data_topic = test_mk_topic_name("0190-data", 1);
        const char *group_id   = test_mk_topic_name("0190-share-grp", 0);
        seen_metrics_t seen    = {0};

        SUB_TEST();

        produce_and_share_consume(data_topic, group_id);

        consume_telemetry_topic(telemetry_topic(), 30, &seen);
        verify_metrics(&seen);

        SUB_TEST_PASS();
}


int main_0190_share_consumer_telemetry(int argc, char **argv) {
        test_timeout_set(180);

        if (!telemetry_infra_available(telemetry_topic())) {
                TEST_SKIP(
                    "telemetry topic '%s' not found — "
                    "OTel/plugin pipeline not configured for this run\n",
                    telemetry_topic());
                return 0;
        }

        do_test_produce_share_consume_verify_metrics();

        return 0;
}
