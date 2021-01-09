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


#define _MSG_COUNT 10
struct latconf {
        const char *name;
        const char *conf[16];
        int min;    /* Minimum expected latency */
        int max;    /* Maximum expected latency */

        float rtt;  /* Network+broker latency */


        char        linger_ms_conf[32]; /**< Read back to show actual value */

        /* Result vector */
        float latency[_MSG_COUNT];
        float sum;
        int   cnt;
};


static void dr_msg_cb (rd_kafka_t *rk,
                       const rd_kafka_message_t *rkmessage, void *opaque) {
        struct latconf *latconf = opaque;
        int64_t *ts_send = (int64_t *)rkmessage->_private;
        float delivery_time;

        if (rkmessage->err)
                TEST_FAIL("%s: delivery failed: %s\n",
                          latconf->name, rd_kafka_err2str(rkmessage->err));

        if (!rkmessage->_private)
                return; /* Priming message, ignore. */

        delivery_time = (float)(test_clock() - *ts_send) / 1000.0f;

        free(ts_send);

        TEST_ASSERT(latconf->cnt < _MSG_COUNT, "");

        TEST_SAY("%s: Message %d delivered in %.3fms\n",
                 latconf->name, latconf->cnt, delivery_time);

        latconf->latency[latconf->cnt++] = delivery_time;
        latconf->sum += delivery_time;
}


static int verify_latency (struct latconf *latconf) {
        float avg;
        int fails = 0;
        double ext_overhead = latconf->rtt +
                5.0 /* broker ProduceRequest handling time, maybe */;

        ext_overhead *= test_timeout_multiplier;

        avg = latconf->sum / (float)latconf->cnt;

        TEST_SAY("%s: average latency %.3fms, allowed range %d..%d +%.0fms\n",
                 latconf->name, avg, latconf->min, latconf->max, ext_overhead);

        if (avg < (float)latconf->min ||
            avg > (float)latconf->max + ext_overhead) {
                TEST_FAIL_LATER("%s: average latency %.3fms is "
                                "outside range %d..%d +%.0fms",
                                latconf->name, avg, latconf->min, latconf->max,
                                ext_overhead);
                fails++;
        }

        return fails;
}

static void measure_rtt (struct latconf *latconf, rd_kafka_t *rk) {
        rd_kafka_resp_err_t err;
        const struct rd_kafka_metadata *md;
        int64_t ts = test_clock();

        err = rd_kafka_metadata(rk, 0, NULL, &md, tmout_multip(5000));
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        latconf->rtt = (float)(test_clock() - ts) / 1000.0f;

        TEST_SAY("%s: broker base RTT is %.3fms\n",
                 latconf->name, latconf->rtt);
        rd_kafka_metadata_destroy(md);
}

static int test_producer_latency (const char *topic,
                                  struct latconf *latconf) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_resp_err_t err;
        int i;
        size_t sz;

        test_conf_init(&conf, NULL, 60);

        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);
        rd_kafka_conf_set_opaque(conf, latconf);

        TEST_SAY(_C_BLU "[%s: begin]\n" _C_CLR, latconf->name);
        for (i = 0 ; latconf->conf[i] ; i += 2) {
                TEST_SAY("%s:  set conf %s = %s\n",
                         latconf->name, latconf->conf[i], latconf->conf[i+1]);
                test_conf_set(conf, latconf->conf[i], latconf->conf[i+1]);
        }

        sz = sizeof(latconf->linger_ms_conf);
        rd_kafka_conf_get(conf, "linger.ms", latconf->linger_ms_conf, &sz);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_SAY("%s: priming producer\n", latconf->name);
        /* Send a priming message to make sure everything is up
         * and functional before starting measurements */
        err = rd_kafka_producev(rk,
                                RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_PARTITION(0),
                                RD_KAFKA_V_VALUE("priming", 7),
                                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                RD_KAFKA_V_END);
        if (err)
                TEST_FAIL("%s: priming producev failed: %s",
                          latconf->name, rd_kafka_err2str(err));

        /* Await delivery */
        rd_kafka_flush(rk, tmout_multip(5000));

        /* Get a network+broker round-trip-time base time. */
        measure_rtt(latconf, rk);

        TEST_SAY("%s: producing %d messages\n", latconf->name, _MSG_COUNT);
        for (i = 0 ; i < _MSG_COUNT ; i++) {
                int64_t *ts_send;

                ts_send = malloc(sizeof(*ts_send));
                *ts_send = test_clock();

                err = rd_kafka_producev(rk,
                                        RD_KAFKA_V_TOPIC(topic),
                                        RD_KAFKA_V_PARTITION(0),
                                        RD_KAFKA_V_VALUE("hi", 2),
                                        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                        RD_KAFKA_V_OPAQUE(ts_send),
                                        RD_KAFKA_V_END);
                if (err)
                        TEST_FAIL("%s: producev #%d failed: %s",
                                  latconf->name, i, rd_kafka_err2str(err));

                /* Await delivery */
                rd_kafka_flush(rk, 5000);
        }

        rd_kafka_destroy(rk);

        return verify_latency(latconf);
}


static float find_min (const struct latconf *latconf) {
        int i;
        float v = 1000000;

        for (i = 0 ; i < latconf->cnt ; i++)
                if (latconf->latency[i] < v)
                        v = latconf->latency[i];

        return v;
}

static float find_max (const struct latconf *latconf) {
        int i;
        float v = 0;

        for (i = 0 ; i < latconf->cnt ; i++)
                if (latconf->latency[i] > v)
                        v = latconf->latency[i];

        return v;
}

int main_0055_producer_latency (int argc, char **argv) {
        struct latconf latconfs[] = {
                { "standard settings", {NULL}, 5, 5 }, /* default is now 5ms */
                { "low queue.buffering.max.ms",
                  {"queue.buffering.max.ms", "0", NULL}, 0, 0 },
                { "microsecond queue.buffering.max.ms",
                  {"queue.buffering.max.ms", "0.001", NULL}, 0, 1 },
                { "high queue.buffering.max.ms",
                  {"queue.buffering.max.ms", "3000", NULL}, 3000, 3100},
                { "queue.buffering.max.ms < 1000", /* internal block_max_ms */
                  {"queue.buffering.max.ms", "500", NULL}, 500, 600 },
                { "no acks",
                  {"queue.buffering.max.ms", "0",
                   "acks", "0",
                   "enable.idempotence", "false", NULL}, 0, 0 },
                { NULL }
        };
        struct latconf *latconf;
        const char *topic = test_mk_topic_name("0055_producer_latency", 0);
        int fails = 0;

        if (test_on_ci) {
                TEST_SKIP("Latency measurements not reliable on CI\n");
                return 0;
        }

        /* Create topic */
        test_produce_msgs_easy(topic, 0, 0, 1);

        for (latconf = latconfs ; latconf->name ; latconf++)
                fails += test_producer_latency(topic, latconf);

        if (fails)
                TEST_FAIL("See %d previous failure(s)", fails);

        TEST_SAY(_C_YEL "Latency tests summary:\n" _C_CLR);
        TEST_SAY("%-40s %9s  %6s..%-6s  %7s  %9s %9s %9s\n",
                 "Name", "linger.ms",
                 "MinExp", "MaxExp", "RTT", "Min", "Average", "Max");

        for (latconf = latconfs ; latconf->name ; latconf++)
                TEST_SAY("%-40s %9s  %6d..%-6d  %7g  %9g %9g %9g\n",
                         latconf->name, latconf->linger_ms_conf,
                         latconf->min, latconf->max,
                         latconf->rtt,
                         find_min(latconf),
                         latconf->sum / latconf->cnt,
                         find_max(latconf));

        return 0;
}
