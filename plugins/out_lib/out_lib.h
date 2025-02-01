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

#ifndef FLB_OUT_LIB
#define FLB_OUT_LIB

#include <fluent-bit/flb_output_plugin.h>

enum {
    FLB_OUT_LIB_FMT_MSGPACK = 0,
    FLB_OUT_LIB_FMT_JSON,
    FLB_OUT_LIB_FMT_ERROR,
};

#define FLB_FMT_STR_MSGPACK "msgpack"
#define FLB_FMT_STR_JSON    "json"

#define FLB_DATA_MODE_SINGLE_RECORD  0 /* "single_record" */
#define FLB_DATA_MODE_CHUNK          1 /* "chunk" */

struct flb_out_lib_config {
    int format;
    int max_records;
    int data_mode;
    flb_sds_t data_mode_str;
    int (*cb_func)(void *record, size_t size, void *data);
    void *cb_data;
    struct flb_output_instance *ins;
};

#endif
