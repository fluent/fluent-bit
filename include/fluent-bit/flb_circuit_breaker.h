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

#ifndef FLB_CIRCUIT_BREAKER_H
#define FLB_CIRCUIT_BREAKER_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>

#define FLB_CIRCUIT_BREAKER_CLOSED      0
#define FLB_CIRCUIT_BREAKER_OPEN        1
#define FLB_CIRCUIT_BREAKER_HALFOPEN    2

#define DEFAULT_CB_CALCULATE_INTERVAL 10
#define DEFAULT_CB_SLEEP_WINDOW 10
#define DEFAULT_CB_MINIMUM_REQUESTS_TO_OPEN 0
#define DEFAULT_CB_ERROR_PERCENT_THRESHOLD 10
#define DEFAULT_CB_REQUIRED_CONSECUTIVE_SUCCESSES 5
#define DEFAULT_CB_REQUIRED_CONSECUTIVE_FAILURES 5

/* Circuit Breaker settings
 * ------------------------
 * The circuit breaker has 3 states, CLOSE, OPEN and HALF_OPEN.
 *
 * The circuit starts in CLOSE state by default; This means that the
 * `flb_cb_allow_request` funcs will be excuted, the circuit will
 * record the results of the executed funcs using cmt_metrics.
 *
 * The implementation of the circuit breaker is based on the
 * time-based sliding window to calculate the error percentage.
 *
 * Being in the CLOSED state: means that when the error percent is
 * greater that the configured threshold in `error_percent_threshold`
 * setting and at least it made N executions configured in
 * `minimum_requests_to_open` OR when the consecutive failures exceed
 * `required_consecutive_failures` will move to OPEN state.
 *
 * Being in the OPEN state: means that the circuit will return directly
 * an error without executing. When the circuit has been in open state
 * for a configured in `sleep_window_in_open_state` which is a
 * period of the open state, after which the state will move to
 * HALF OPEN state.
 *
 * Being in the HALF OPEN state: means that the circuit will check that
 * when `required_consecutive_successes` have been made if all of them
 * have been successful. If all have been OK, it will move to closed state,
 * if not it will move to open state.
 *
 * */
struct flb_circuit_breaker {
    const char *output_name;                        /* Output Instance name */
    int enabled;                                    /* circuit breaker enabled? (default:off)                         */
    int error_percent_threshold;                    /* number of failures we receive from the upstream                */
    uint64_t calculate_interval;                    /* cyclic period of the closed state                              */
    uint64_t sleep_window_in_open_state;            /* sleep window in the open state                                 */
    int minimum_requests_to_open;                   /* minimum number of requests to open the circuit                 */
    int required_consecutive_successes;             /* required consecutive successes to close circuit from half-open */
    int required_consecutive_failures;              /* required consecutive errors to open circuit from closed        */
    int state;                                      /* current state: open, half-open, closed                         */
    uint64_t last_opened_time;                      /* opened or last tested time                                     */
    uint64_t last_calculated_time;                  /* opened or last tested time                                     */
    struct flb_circuit_breaker_metrics *metrics;
};

struct flb_circuit_breaker_metrics {
    struct cmt_metric *total_successes;             /* total success requests in T sliding window                     */
    struct cmt_metric *total_failures;              /* total failure requests in T sliding window                     */
    struct cmt_metric *consecutive_successes;       /* consecutive success requests                                   */
    struct cmt_metric *consecutive_failures;        /* consecutive failure requests                                   */
};

struct flb_circuit_breaker *flb_circuit_breaker_create(const char *output_name,
                                                       int enabled,
                                                       int error_percent_threshold,
                                                       int sleep_window,
                                                       int calculate_interval,
                                                       int minimum_requests_to_open,
                                                       int required_consecutive_successes,
                                                       int required_consecutive_failures);

int flb_circuit_breaker_allow_request(struct flb_circuit_breaker *circuit_breaker);

int flb_circuit_breaker_is_after_sleep_window(struct flb_circuit_breaker *circuit_breaker, uint64_t now);

void flb_circuit_breaker_set_open(struct flb_circuit_breaker *circuit_breaker, uint64_t now);

void flb_circuit_breaker_set_close(struct flb_circuit_breaker *circuit_breaker);

void flb_circuit_breaker_move_state(struct flb_circuit_breaker *circuit_breaker, int newState, uint64_t now);

void flb_circuit_breaker_calculate_current_state(struct flb_circuit_breaker *circuit_breaker, uint64_t now);

int flb_circuit_breaker_decide_state(struct flb_circuit_breaker *circuit_breaker,
                        double successes,
                        double failures,
                        double error_rate);

struct flb_circuit_breaker_metrics *flb_circuit_breaker_metrics_create();

void flb_circuit_breaker_on_success(struct flb_circuit_breaker *circuit_breaker);

void flb_circuit_breaker_on_failure(struct flb_circuit_breaker *circuit_breaker);

void flb_circuit_breaker_reset(struct flb_circuit_breaker *circuit_breaker);

int flb_circuit_breaker_destroy(struct flb_circuit_breaker *circuit_breaker);

#endif //FLUENT_BIT_FLB_CIRCUIT_BREAKER_H
