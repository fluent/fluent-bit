/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_OUTPUT_THROTTLE_H
#define FLB_OUTPUT_THROTTLE_H

#include <stdint.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_pthread.h>

#define FLB_OUTPUT_THROTTLE_READY     0
#define FLB_OUTPUT_THROTTLE_COOLDOWN  1
#define FLB_OUTPUT_THROTTLE_STOPPING  2

struct flb_output_throttle {
    int enabled;
    int state;
    uint64_t base_ms;
    uint64_t cap_ms;
    uint64_t started_ms;
    uint64_t until_ms;
    uint64_t generation;
    uint32_t consecutive_rounds;
    uint64_t events;
    pthread_mutex_t lock;
};

struct flb_output_throttle_snapshot {
    int enabled;
    int state;
    uint64_t started_ms;
    uint64_t until_ms;
    uint64_t generation;
    uint32_t consecutive_rounds;
    uint64_t events;
};

int flb_output_throttle_init(struct flb_output_throttle *throttle,
                             int enabled, uint64_t base_ms, uint64_t cap_ms);
void flb_output_throttle_destroy(struct flb_output_throttle *throttle);
int flb_output_throttle_admit(struct flb_output_throttle *throttle,
                              uint64_t now_ms, uint64_t *generation);
uint64_t flb_output_throttle_publish(struct flb_output_throttle *throttle,
                                     uint64_t now_ms, int hint_present,
                                     uint64_t hint_ms, uint64_t random_value);
void flb_output_throttle_success(struct flb_output_throttle *throttle,
                                 uint64_t now_ms, uint64_t generation);
void flb_output_throttle_stop(struct flb_output_throttle *throttle);
void flb_output_throttle_snapshot(struct flb_output_throttle *throttle,
                                  struct flb_output_throttle_snapshot *snapshot);
uint64_t flb_output_throttle_now_ms(void);

#endif
