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

#if WITH_SOCKEM
#include "rdkafka.h"

#include <stdarg.h>
#include <errno.h>

/**
 * Request retry testing
 */

/* Hang on to the first broker socket we see in connect_cb,
 * reject all the rest (connection refused) to make sure we're only
 * playing with one single broker for this test. */
static struct {
        mtx_t lock;
        cnd_t cnd;
        sockem_t *skm;
        thrd_t thrd;
        struct {
                int64_t ts_at; /* to ctrl thread: at this time, set delay */
                int delay;
                int ack; /* from ctrl thread: new delay acked */
        } cmd;
        struct {
                int64_t ts_at; /* to ctrl thread: at this time, set delay */
                int delay;

        } next;
        int term;
} ctrl;

static int ctrl_thrd_main(void *arg) {


        mtx_lock(&ctrl.lock);
        while (!ctrl.term) {
                int64_t now;

                cnd_timedwait_ms(&ctrl.cnd, &ctrl.lock, 10);

                if (ctrl.cmd.ts_at) {
                        ctrl.next.ts_at = ctrl.cmd.ts_at;
                        ctrl.next.delay = ctrl.cmd.delay;
                        ctrl.cmd.ts_at  = 0;
                        ctrl.cmd.ack    = 1;
                        printf(_C_CYA
                               "## %s: sockem: "
                               "receieved command to set delay "
                               "to %d in %dms\n" _C_CLR,
                               __FILE__, ctrl.next.delay,
                               (int)(ctrl.next.ts_at - test_clock()) / 1000);
                }

                now = test_clock();
                if (ctrl.next.ts_at && now > ctrl.next.ts_at) {
                        assert(ctrl.skm);
                        printf(_C_CYA
                               "## %s: "
                               "sockem: setting socket delay to %d\n" _C_CLR,
                               __FILE__, ctrl.next.delay);
                        sockem_set(ctrl.skm, "delay", ctrl.next.delay, NULL);
                        ctrl.next.ts_at = 0;
                        cnd_signal(&ctrl.cnd); /* signal back to caller */
                }
        }
        mtx_unlock(&ctrl.lock);

        return 0;
}


/**
 * @brief Sockem connect, called from **internal librdkafka thread** through
 *        librdkafka's connect_cb
 */
static int connect_cb(struct test *test, sockem_t *skm, const char *id) {

        mtx_lock(&ctrl.lock);
        if (ctrl.skm) {
                /* Reject all but the first connect */
                mtx_unlock(&ctrl.lock);
                return ECONNREFUSED;
        }

        ctrl.skm = skm;

        /* signal wakeup to main thread */
        cnd_broadcast(&ctrl.cnd);
        mtx_unlock(&ctrl.lock);

        return 0;
}

static int
is_fatal_cb(rd_kafka_t *rk, rd_kafka_resp_err_t err, const char *reason) {
        /* Ignore connectivity errors since we'll be bringing down
         * .. connectivity.
         * SASL auther will think a connection-down even in the auth
         * state means the broker doesn't support SASL PLAIN. */
        TEST_SAY("is_fatal?: %s: %s\n", rd_kafka_err2str(err), reason);
        if (err == RD_KAFKA_RESP_ERR__TRANSPORT ||
            err == RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN ||
            err == RD_KAFKA_RESP_ERR__AUTHENTICATION ||
            err == RD_KAFKA_RESP_ERR__TIMED_OUT)
                return 0;
        return 1;
}

/**
 * @brief Set socket delay to kick in after \p after ms
 */
static void set_delay(int after, int delay) {
        TEST_SAY("Set delay to %dms (after %dms)\n", delay, after);

        mtx_lock(&ctrl.lock);
        ctrl.cmd.ts_at = test_clock() + (after * 1000);
        ctrl.cmd.delay = delay;
        ctrl.cmd.ack   = 0;
        cnd_broadcast(&ctrl.cnd);

        /* Wait for ack from sockem thread */
        while (!ctrl.cmd.ack) {
                TEST_SAY("Waiting for sockem control ack\n");
                cnd_timedwait_ms(&ctrl.cnd, &ctrl.lock, 1000);
        }
        mtx_unlock(&ctrl.lock);
}

/**
 * @brief Test that Metadata requests are retried properly when
 *        timing out due to high broker rtt.
 */
static void do_test_low_socket_timeout(const char *topic) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        rd_kafka_resp_err_t err;
        const struct rd_kafka_metadata *md;
        int res;

        mtx_init(&ctrl.lock, mtx_plain);
        cnd_init(&ctrl.cnd);

        TEST_SAY("Test Metadata request retries on timeout\n");

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "socket.timeout.ms", "1000");
        test_conf_set(conf, "socket.max.fails", "12345");
        test_conf_set(conf, "retry.backoff.ms", "5000");
        /* Avoid api version requests (with their own timeout) to get in
         * the way of our test */
        test_conf_set(conf, "api.version.request", "false");
        test_socket_enable(conf);
        test_curr->connect_cb  = connect_cb;
        test_curr->is_fatal_cb = is_fatal_cb;

        rk  = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = test_create_producer_topic(rk, topic, NULL);

        TEST_SAY("Waiting for sockem connect..\n");
        mtx_lock(&ctrl.lock);
        while (!ctrl.skm)
                cnd_wait(&ctrl.cnd, &ctrl.lock);
        mtx_unlock(&ctrl.lock);

        TEST_SAY(
            "Connected, fire off a undelayed metadata() to "
            "make sure connection is up\n");

        err = rd_kafka_metadata(rk, 0, rkt, &md, tmout_multip(2000));
        TEST_ASSERT(!err, "metadata(undelayed) failed: %s",
                    rd_kafka_err2str(err));
        rd_kafka_metadata_destroy(md);

        if (thrd_create(&ctrl.thrd, ctrl_thrd_main, NULL) != thrd_success)
                TEST_FAIL("Failed to create sockem ctrl thread");

        set_delay(0, 3000); /* Takes effect immediately */

        /* After two retries, remove the delay, the third retry
         * should kick in and work. */
        set_delay(
            ((1000 /*socket.timeout.ms*/ + 5000 /*retry.backoff.ms*/) * 2) -
                2000,
            0);

        TEST_SAY(
            "Calling metadata() again which should succeed after "
            "3 internal retries\n");
        /* Metadata should be returned after the third retry */
        err = rd_kafka_metadata(
            rk, 0, rkt, &md,
            ((1000 /*socket.timeout.ms*/ + 5000 /*retry.backoff.ms*/) * 2) +
                5000);
        TEST_SAY("metadata() returned %s\n", rd_kafka_err2str(err));
        TEST_ASSERT(!err, "metadata(undelayed) failed: %s",
                    rd_kafka_err2str(err));
        rd_kafka_metadata_destroy(md);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        /* Join controller thread */
        mtx_lock(&ctrl.lock);
        ctrl.term = 1;
        mtx_unlock(&ctrl.lock);
        thrd_join(ctrl.thrd, &res);

        cnd_destroy(&ctrl.cnd);
        mtx_destroy(&ctrl.lock);
}

int main_0075_retry(int argc, char **argv) {
        const char *topic = test_mk_topic_name("0075_retry", 1);

        do_test_low_socket_timeout(topic);

        return 0;
}


#endif
