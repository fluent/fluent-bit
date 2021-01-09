/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#define DEFAULT_DUMMY_MESSAGE "{\"message\":\"dummy\"}"

struct flb_dummy {
    int samples;
    int samples_count;
    char *dummy_message;
    int    dummy_message_len;

    char *ref_msgpack;
    size_t ref_msgpack_size;

    struct flb_time *dummy_timestamp;
    struct flb_time *base_timestamp;
    struct flb_input_instance *ins;
};

#endif
