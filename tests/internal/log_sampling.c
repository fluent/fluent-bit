/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>

#include "flb_tests_internal.h"

/* Import the sampling functions from the processor plugin */
#include "../../plugins/processor_log_sampling/log_sampling.h"

static void test_fixed_window_basic()
{
    struct sampling_state state = {0};
    int result;
    int i;
    int sampled_count = 0;
    time_t current_time = 1000;  /* Start time */
    int window_size = 60;
    int max_logs = 5;
    
    /* Initialize state */
    state.window_start = current_time;
    state.current_window_count = 0;
    
    /* Test: First 5 logs should be sampled */
    for (i = 0; i < 10; i++) {
        result = flb_sampling_fixed_window(&state, current_time, window_size, max_logs);
        if (result == FLB_TRUE) {
            sampled_count++;
        }
    }
    
    TEST_CHECK(sampled_count == 5);
    TEST_MSG("Fixed window: sampled %d out of 10 (expected 5)", sampled_count);
    
    /* Test: New window should reset the count */
    current_time += window_size + 1;  /* Move to next window */
    sampled_count = 0;
    
    for (i = 0; i < 3; i++) {
        result = flb_sampling_fixed_window(&state, current_time, window_size, max_logs);
        if (result == FLB_TRUE) {
            sampled_count++;
        }
    }
    
    TEST_CHECK(sampled_count == 3);
    TEST_MSG("Fixed window (new): sampled %d out of 3 (expected 3)", sampled_count);
}

static void test_sliding_window_basic()
{
    struct sampling_state state = {0};
    int result;
    int i;
    int sampled_count = 0;
    time_t current_time = 1000;
    int window_size = 10;
    int max_logs = 5;
    
    /* Initialize sliding window buckets */
    state.bucket_count = window_size;
    state.buckets = flb_calloc(state.bucket_count, sizeof(*state.buckets));
    TEST_CHECK(state.buckets != NULL);
    
    /* Test: First 5 logs should be sampled */
    for (i = 0; i < 7; i++) {
        result = flb_sampling_sliding_window(&state, current_time, window_size, max_logs);
        if (result == FLB_TRUE) {
            sampled_count++;
        }
        /* Advance time slightly to distribute across buckets */
        if (i % 2 == 0) {
            current_time++;
        }
    }
    
    TEST_CHECK(sampled_count == 5);
    TEST_MSG("Sliding window: sampled %d out of 7 (expected 5)", sampled_count);
    
    /* Test: Old entries should expire */
    current_time += window_size + 2;  /* Move past window */
    sampled_count = 0;
    
    for (i = 0; i < 3; i++) {
        result = flb_sampling_sliding_window(&state, current_time, window_size, max_logs);
        if (result == FLB_TRUE) {
            sampled_count++;
        }
    }
    
    TEST_CHECK(sampled_count == 3);
    TEST_MSG("Sliding window (after expiry): sampled %d out of 3 (expected 3)", sampled_count);
    
    flb_free(state.buckets);
}

static void test_exponential_decay_basic()
{
    int result;
    int i;
    int sampled_count;
    time_t window_start = 1000;
    time_t current_time = 1000;
    double base_rate = 1.0;  /* 100% initially */
    double decay_factor = 0.5;  /* 50% reduction per interval */
    int decay_interval = 10;
    
    /* Seed random for reproducible tests */
    srand(12345);
    
    /* Test: First interval should sample most logs (rate=1.0) */
    sampled_count = 0;
    for (i = 0; i < 100; i++) {
        result = flb_sampling_exponential(window_start, current_time, 
                                         base_rate, decay_factor, decay_interval);
        if (result == FLB_TRUE) {
            sampled_count++;
        }
    }
    
    /* With rate=1.0, should sample all or nearly all */
    TEST_CHECK(sampled_count >= 95);
    TEST_MSG("Exponential (interval 0): sampled %d out of 100 (expected >= 95)", sampled_count);
    
    /* Test: Second interval should sample about 50% */
    current_time = window_start + decay_interval;
    sampled_count = 0;
    
    for (i = 0; i < 100; i++) {
        result = flb_sampling_exponential(window_start, current_time,
                                         base_rate, decay_factor, decay_interval);
        if (result == FLB_TRUE) {
            sampled_count++;
        }
    }
    
    /* With rate=0.5, should sample roughly 40-60% */
    TEST_CHECK(sampled_count >= 40 && sampled_count <= 60);
    TEST_MSG("Exponential (interval 1): sampled %d out of 100 (expected 40-60)", sampled_count);
    
    /* Test: Third interval should sample about 25% */
    current_time = window_start + (2 * decay_interval);
    sampled_count = 0;
    
    for (i = 0; i < 100; i++) {
        result = flb_sampling_exponential(window_start, current_time,
                                         base_rate, decay_factor, decay_interval);
        if (result == FLB_TRUE) {
            sampled_count++;
        }
    }
    
    /* With rate=0.25, should sample roughly 20-30% */
    TEST_CHECK(sampled_count >= 15 && sampled_count <= 35);
    TEST_MSG("Exponential (interval 2): sampled %d out of 100 (expected 15-35)", sampled_count);
}

static void test_fixed_window_edge_cases()
{
    struct sampling_state state = {0};
    int result;
    time_t current_time = 1000;
    int window_size = 60;
    int max_logs = 0;  /* Edge case: no logs allowed */
    
    /* Test: max_logs = 0 should reject all */
    state.window_start = current_time;
    state.current_window_count = 0;
    
    result = flb_sampling_fixed_window(&state, current_time, window_size, max_logs);
    TEST_CHECK(result == FLB_FALSE);
    
    /* Test: Window boundary */
    max_logs = 1;
    state.current_window_count = 0;
    
    result = flb_sampling_fixed_window(&state, current_time, window_size, max_logs);
    TEST_CHECK(result == FLB_TRUE);
    
    /* Move to exact window boundary */
    current_time = state.window_start + window_size;
    result = flb_sampling_fixed_window(&state, current_time, window_size, max_logs);
    TEST_CHECK(result == FLB_TRUE);  /* New window should allow */
    TEST_CHECK(state.current_window_count == 1);
}

static void test_sliding_window_edge_cases()
{
    struct sampling_state state = {0};
    int result;
    time_t current_time = 1000;
    int window_size = 1;  /* Minimal window */
    int max_logs = 1;
    
    /* Initialize with minimal bucket */
    state.bucket_count = 1;
    state.buckets = flb_calloc(1, sizeof(*state.buckets));
    TEST_CHECK(state.buckets != NULL);
    
    /* Test: Single bucket behavior */
    result = flb_sampling_sliding_window(&state, current_time, window_size, max_logs);
    TEST_CHECK(result == FLB_TRUE);
    
    result = flb_sampling_sliding_window(&state, current_time, window_size, max_logs);
    TEST_CHECK(result == FLB_FALSE);  /* Already at limit */
    
    /* Test: Bucket expiry */
    current_time += window_size + 1;
    result = flb_sampling_sliding_window(&state, current_time, window_size, max_logs);
    TEST_CHECK(result == FLB_TRUE);  /* Old bucket should be expired */
    
    flb_free(state.buckets);
}

TEST_LIST = {
    { "fixed_window_basic", test_fixed_window_basic },
    { "sliding_window_basic", test_sliding_window_basic },
    { "exponential_decay_basic", test_exponential_decay_basic },
    { "fixed_window_edge_cases", test_fixed_window_edge_cases },
    { "sliding_window_edge_cases", test_sliding_window_edge_cases },
    { 0 }
};