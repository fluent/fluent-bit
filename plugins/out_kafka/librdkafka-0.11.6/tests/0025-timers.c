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
 * Tests that rdkafka's internal timers behave.
 */



struct state {
        int calls;
        int64_t ts_last;
        int interval;
        int fails;
};

struct state state;


static int stats_cb (rd_kafka_t *rk, char *json, size_t json_len,
                      void *opaque) {
        const int64_t now = test_clock();
        /* Fake the first elapsed time since we dont really know how
         * long rd_kafka_new() takes and at what time the timer is started. */
        const int64_t elapsed = state.ts_last ?
                now - state.ts_last : state.interval;
        const int64_t overshoot = elapsed - state.interval;
        const int wiggleroom_up = (int)((double)state.interval *
					(!strcmp(test_mode, "bare") ? 0.2 : 1.0));
	const int wiggleroom_down = (int)((double)state.interval * 0.1);

        TEST_SAY("Call #%d: after %"PRId64"ms, %.0f%% outside "
                 "interval %"PRId64"  >-%d <+%d\n",
                 state.calls, elapsed / 1000,
                 ((double)overshoot / state.interval) * 100.0,
                 (int64_t)state.interval / 1000,
		 wiggleroom_down / 1000, wiggleroom_up / 1000);

        if (overshoot < -wiggleroom_down || overshoot > wiggleroom_up) {
                TEST_WARN("^ outside range\n");
                state.fails++;
        }

        state.ts_last = now;
        state.calls++;

        return 0;
}


/**
 * Enable statistics with a set interval, make sure the stats callbacks are
 * called within reasonable intervals.
 */
static void do_test_stats_timer (void) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        const int exp_calls = 10;
        test_timing_t t_new;

        memset(&state, 0, sizeof(state));

        state.interval = 600*1000;

        test_conf_init(&conf, NULL, 200);

        test_conf_set(conf, "statistics.interval.ms", "600");
        test_conf_set(conf, "bootstrap.servers", NULL); /*no need for brokers*/
        rd_kafka_conf_set_stats_cb(conf, stats_cb);

        TIMING_START(&t_new, "rd_kafka_new()");
        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);
        TIMING_STOP(&t_new);

        TEST_SAY("Starting wait loop for %d expected stats_cb calls "
                 "with an interval of %dms\n",
                 exp_calls, state.interval/1000);


        while (state.calls < exp_calls) {
                test_timing_t t_poll;
                TIMING_START(&t_poll, "rd_kafka_poll()");
                rd_kafka_poll(rk, 100);
                TIMING_STOP(&t_poll);

                if (TIMING_DURATION(&t_poll) > 150*1000)
                        TEST_WARN("rd_kafka_poll(rk,100) "
                                  "took more than 50%% extra\n");
        }

        rd_kafka_destroy(rk);

        if (state.calls > exp_calls)
                TEST_SAY("Got more calls than expected: %d > %d\n",
                         state.calls, exp_calls);

        if (state.fails) {
                /* We can't rely on CIs giving our test job enough CPU to finish
                 * in time, so don't error out even if the time is outside
                 * the window */
                if (test_on_ci)
                        TEST_WARN("%d/%d intervals failed\n",
                                  state.fails, state.calls);
                else
                        TEST_FAIL("%d/%d intervals failed\n",
                                  state.fails, state.calls);
        } else
                TEST_SAY("All %d intervals okay\n", state.calls);
}


int main_0025_timers (int argc, char **argv) {
        do_test_stats_timer();
        return 0;
}
