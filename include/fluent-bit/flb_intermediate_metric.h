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

/* Fluent Bit intermediate metric representation */

#ifndef FLB_INTERMEDIATE_METRIC_H
#define FLB_INTERMEDIATE_METRIC_H

#include <fluent-bit/flb_time.h>
#include <monkey/mk_core.h>
#include <msgpack.h>

/* Metric Type- Gague or Counter */
#define GAUGE 1
#define COUNTER 2

/* Metric Unit */
#define PERCENT "Percent"
#define BYTES "Bytes"

struct flb_intermediate_metric
{
    msgpack_object key;
    msgpack_object value;
    int metric_type;
    const char *metric_unit;
    struct flb_time timestamp;

    struct mk_list _head;
};

#endif