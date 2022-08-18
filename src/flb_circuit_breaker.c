/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Metrics interface is a helper to gather general metrics from the core or
 * plugins at runtime.
 */

#include <math.h>

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_circuit_breaker.h>
#include <fluent-bit/flb_time.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>

struct flb_circuit_breaker *flb_circuit_breaker_create(const char *output_name,
                                                       int enabled,
                                                       int error_percent_threshold,
                                                       int sleep_window,
                                                       int calculate_interval,
                                                       int minimum_requests_to_open,
                                                       int required_consecutive_successes,
                                                       int required_consecutive_failures)
{
    struct flb_circuit_breaker *circuit_breaker;

    circuit_breaker = flb_malloc(sizeof(struct flb_circuit_breaker));
    if (!circuit_breaker) {
        return NULL;
    }

    circuit_breaker->metrics = flb_circuit_breaker_metrics_create();
    if (!circuit_breaker->metrics) {
        flb_circuit_breaker_destroy(circuit_breaker);
        return NULL;
    }

    // Set default values if not provided
    if (calculate_interval <= 0) {
        calculate_interval = DEFAULT_CB_CALCULATE_INTERVAL;
    }
    if (sleep_window <= 0) {
        sleep_window = DEFAULT_CB_SLEEP_WINDOW;
    }
    if (error_percent_threshold <= 0) {
        error_percent_threshold = DEFAULT_CB_ERROR_PERCENT_THRESHOLD;
    }
    if (minimum_requests_to_open <= 0) {
        minimum_requests_to_open = DEFAULT_CB_MINIMUM_REQUESTS_TO_OPEN;
    }
    if (required_consecutive_successes <= 0) {
        required_consecutive_successes = DEFAULT_CB_REQUIRED_CONSECUTIVE_SUCCESSES;
    }
    if (required_consecutive_failures <= 0) {
        required_consecutive_failures = DEFAULT_CB_REQUIRED_CONSECUTIVE_FAILURES;
    }

    circuit_breaker->output_name = output_name;
    circuit_breaker->enabled = enabled;
    circuit_breaker->error_percent_threshold = error_percent_threshold;
    circuit_breaker->minimum_requests_to_open = minimum_requests_to_open;
    circuit_breaker->required_consecutive_successes = required_consecutive_successes;
    circuit_breaker->required_consecutive_failures = required_consecutive_failures;

    struct flb_time calc, sleep;
    flb_time_from_double(&calc, (double)calculate_interval);
    flb_time_from_double(&sleep,  (double)sleep_window);

    circuit_breaker->calculate_interval = flb_time_to_nanosec(&calc);
    circuit_breaker->sleep_window_in_open_state = flb_time_to_nanosec(&sleep);

    circuit_breaker->last_opened_time = 0;
    circuit_breaker->last_calculated_time = 0;

    flb_circuit_breaker_reset(circuit_breaker);
    flb_circuit_breaker_set_close(circuit_breaker);

    return circuit_breaker;
}

struct flb_circuit_breaker_metrics *flb_circuit_breaker_metrics_create() {
    struct flb_circuit_breaker_metrics *metrics;

    metrics = flb_malloc(sizeof(struct flb_circuit_breaker_metrics));
    if (!metrics) {
        return NULL;
    }

    metrics->total_successes = flb_malloc(sizeof(struct cmt_metric));
    metrics->total_failures = flb_malloc(sizeof(struct cmt_metric));
    metrics->consecutive_successes = flb_malloc(sizeof(struct cmt_metric));
    metrics->consecutive_failures = flb_malloc(sizeof(struct cmt_metric));

    return metrics;
}

int flb_circuit_breaker_allow_request(struct flb_circuit_breaker *circuit_breaker) {
    struct flb_time t;
    flb_time_get(&t);
    uint64_t now = flb_time_to_nanosec(&t);

    flb_circuit_breaker_calculate_current_state(circuit_breaker, now);

    if (circuit_breaker->state == FLB_CIRCUIT_BREAKER_CLOSED) {
        return FLB_TRUE;
    }

    // When the circuit is open, this check will occasionally return true
    // to measure whether the external service has recovered.
    if (flb_circuit_breaker_is_after_sleep_window(circuit_breaker, now) == FLB_TRUE) {
        flb_warn("[circuit_breaker] %s: sleep window has expired, set state HALFOPEN", circuit_breaker->output_name);
        circuit_breaker->last_opened_time = now;
        circuit_breaker->state = FLB_CIRCUIT_BREAKER_HALFOPEN;
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

int flb_circuit_breaker_is_after_sleep_window(struct flb_circuit_breaker *circuit_breaker, uint64_t now) {
    uint64_t last_ns = circuit_breaker->last_opened_time;
    uint64_t final_ns = last_ns + circuit_breaker->sleep_window_in_open_state;
    return (now > final_ns) ? FLB_TRUE : FLB_FALSE;
}

void flb_cb_move_state(struct flb_circuit_breaker *circuit_breaker, int newState, uint64_t now) {
    if (circuit_breaker->state == newState) {
        return;
    }

    if (newState == FLB_CIRCUIT_BREAKER_OPEN) {
        flb_circuit_breaker_set_open(circuit_breaker, now);
    } else if (newState == FLB_CIRCUIT_BREAKER_CLOSED) {
        flb_circuit_breaker_set_close(circuit_breaker);
    }
}

void flb_circuit_breaker_set_open(struct flb_circuit_breaker *circuit_breaker, uint64_t now) {
    if (circuit_breaker->state == FLB_CIRCUIT_BREAKER_OPEN) {
        return;
    }

    flb_warn("[circuit_breaker] %s: set state OPEN", circuit_breaker->output_name);

    circuit_breaker->state = FLB_CIRCUIT_BREAKER_OPEN;
    circuit_breaker->last_opened_time = now;
}

void flb_circuit_breaker_set_close(struct flb_circuit_breaker *circuit_breaker) {
    if (circuit_breaker->state == FLB_CIRCUIT_BREAKER_CLOSED) {
        return;
    }

    flb_warn("[circuit_breaker] %s: set state CLOSED", circuit_breaker->output_name);

    circuit_breaker->state = FLB_CIRCUIT_BREAKER_CLOSED;
    circuit_breaker->last_opened_time = 0;
}

void flb_circuit_breaker_calculate_current_state(struct flb_circuit_breaker *circuit_breaker, uint64_t now) {
    uint64_t last_ns = circuit_breaker->last_calculated_time;
    uint64_t final_ns = circuit_breaker->last_calculated_time + circuit_breaker->calculate_interval;

    if (now > final_ns) {
        double successes = cmt_metric_get_value(circuit_breaker->metrics->total_successes);
        double failures = cmt_metric_get_value(circuit_breaker->metrics->total_failures);
        double total = successes + failures;
        double error_rate = (failures / (total)) * 100;

        if (isnan(error_rate)) {
            return;
        }

        flb_debug("[circuit_breaker] %s: calculated error_rate=%lf total_failures=%lf total_successes=%lf "
                 "consecutive_failures=%lf, consecutive_successes=%lf last_calculated_time=%llu, checking new state...",
                 circuit_breaker->output_name, error_rate, failures, successes,
                 cmt_metric_get_value(circuit_breaker->metrics->consecutive_failures),
                 cmt_metric_get_value(circuit_breaker->metrics->consecutive_successes),
                 last_ns);

        int new_state = flb_circuit_breaker_decide_state(circuit_breaker, successes, failures, error_rate);
        flb_cb_move_state(circuit_breaker, new_state, now);

        flb_circuit_breaker_reset(circuit_breaker);

        circuit_breaker->last_calculated_time = now;
    }
}

int flb_circuit_breaker_decide_state(struct flb_circuit_breaker *circuit_breaker, double successes, double failures, double error_rate) {
    int error_exceeded = error_rate >= circuit_breaker->error_percent_threshold * 100 ? FLB_TRUE : FLB_FALSE;
    int current_state = circuit_breaker->state;

    switch (current_state) {
        case FLB_CIRCUIT_BREAKER_CLOSED:
            if (failures > 0 &&
                successes + failures >= circuit_breaker->minimum_requests_to_open &&
                (error_exceeded == FLB_TRUE ||
                    cmt_metric_get_value(circuit_breaker->metrics->consecutive_failures) >
                    circuit_breaker->required_consecutive_failures)){
                flb_debug("[circuit_breaker] %s: decided next state is OPEN, current state is CLOSED", circuit_breaker->output_name);
                return FLB_CIRCUIT_BREAKER_OPEN;
            }
            break;
        case FLB_CIRCUIT_BREAKER_OPEN:
            /* nothing much to do, wait until next sleep window */
            flb_debug("[circuit_breaker] %s: decided next state is OPEN, current state is OPEN", circuit_breaker->output_name);
            return FLB_CIRCUIT_BREAKER_OPEN;
        case FLB_CIRCUIT_BREAKER_HALFOPEN:
            if (successes > 0 &&
                cmt_metric_get_value(circuit_breaker->metrics->consecutive_successes) >=
                circuit_breaker->required_consecutive_successes) {
                flb_debug("[circuit_breaker] %s: decided next state is CLOSED, current state is HALFOPEN", circuit_breaker->output_name);
                return FLB_CIRCUIT_BREAKER_CLOSED;
            }
            break;
    }

    return current_state;
}

void flb_circuit_breaker_on_success(struct flb_circuit_breaker *circuit_breaker) {
    uint64_t ts = cmt_time_now();
    cmt_metric_inc(circuit_breaker->metrics->total_successes, ts);
    cmt_metric_inc(circuit_breaker->metrics->consecutive_successes, ts);
    cmt_metric_set(circuit_breaker->metrics->consecutive_failures, ts, 0);
}

void flb_circuit_breaker_on_failure(struct flb_circuit_breaker *circuit_breaker) {
    uint64_t ts = cmt_time_now();
    cmt_metric_inc(circuit_breaker->metrics->total_failures, ts);
    cmt_metric_inc(circuit_breaker->metrics->consecutive_failures, ts);
    cmt_metric_set(circuit_breaker->metrics->consecutive_successes, ts, 0);
}

void flb_circuit_breaker_reset(struct flb_circuit_breaker *circuit_breaker) {
    uint64_t ts = cmt_time_now();
    cmt_metric_set(circuit_breaker->metrics->total_successes, ts, 0);
    cmt_metric_set(circuit_breaker->metrics->total_failures, ts, 0);
}

int flb_circuit_breaker_destroy(struct flb_circuit_breaker *circuit_breaker) {
    if (!circuit_breaker) {
        return -1;
    }

    flb_free(circuit_breaker);
    return 0;
}
