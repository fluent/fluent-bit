/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_IN_DUMMY_H
#define FLB_IN_DUMMY_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log_event_encoder.h>

#define DEFAULT_DUMMY_MESSAGE  "{\"message\":\"dummy\"}"
#define DEFAULT_DUMMY_METADATA "{}"
#define DEFAULT_RATE  "1"
#define DEFAULT_INTERVAL_SEC "0"
#define DEFAULT_INTERVAL_NSEC "0"

struct flb_dummy {
    int  coll_fd;

    int  rate;
    int  copies;
    int  samples;
    int  samples_count;
    int  interval_sec;
    int  interval_nsec;

    int dummy_timestamp_set;
    struct flb_time base_timestamp;
    struct flb_time dummy_timestamp;

    int  start_time_sec;
    int  start_time_nsec;

    int fixed_timestamp;
    int flush_on_startup;
    int test_hang_on_exit;  /* TEST ONLY: Used for hot reload watchdog testing */

    char *ref_metadata_msgpack;
    size_t ref_metadata_msgpack_size;

    char *ref_body_msgpack;
    size_t ref_body_msgpack_size;

    struct flb_log_event_encoder *encoder;

    struct flb_input_instance *ins;
};

#endif
