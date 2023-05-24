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

#ifndef FLB_INPUT_METRIC_H
#define FLB_INPUT_METRIC_H

#include <fluent-bit/flb_info.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_encode_msgpack.h>

int flb_input_metrics_append(struct flb_input_instance *ins,
                             const char *tag, size_t tag_len,
                             struct cmt *cmt);

int flb_input_metrics_append_skip_processor_stages(
        struct flb_input_instance *ins,
        size_t processor_starting_stage,
        const char *tag, size_t tag_len,
        struct cmt *cmt);
#endif
