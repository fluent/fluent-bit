/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_OUT_STDOUT
#define FLB_OUT_STDOUT

#define FLB_STDOUT_OUT_MSGPACK      0
#define FLB_STDOUT_OUT_JSON_LINES   1

#define FLB_STDOUT_JSON_DATE_DOUBLE      0
#define FLB_STDOUT_JSON_DATE_ISO8601     1
#define FLB_STDOUT_JSON_DATE_ISO8601_FMT "%Y-%m-%dT%H:%M:%S"

struct flb_out_stdout_config {
    int out_format;

    int json_date_format;
    char *json_date_key;
    size_t json_date_key_len;
};

#endif
