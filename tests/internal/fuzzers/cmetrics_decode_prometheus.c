/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#include <cmetrics/cmt_decode_prometheus.h>


int
LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    struct cmt *cmt = NULL;
    int result;

    /* At least one byte is needed for deciding which decoder to use */
    if (size < 1) {
        return 0;
    }

    struct cmt_decode_prometheus_parse_opts opts;
    result = cmt_decode_prometheus_create(&cmt, data, size, &opts);
    if (result == CMT_DECODE_PROMETHEUS_SUCCESS) {
        cmt_decode_prometheus_destroy(cmt);
    }

    return 0;
}
