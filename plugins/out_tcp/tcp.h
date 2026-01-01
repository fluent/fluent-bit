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

#ifndef FLB_OUT_TCP_H
#define FLB_OUT_TCP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_record_accessor.h>

struct flb_out_tcp {
    /* Output format */
    int out_format;
    flb_sds_t raw_message_key;
    struct flb_record_accessor *ra_raw_message_key;

    char *host;
    int port;

    /* Timestamp format */
    int       json_date_format;
    flb_sds_t json_date_key;
    flb_sds_t date_key;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    struct flb_output_instance *ins;
};

#endif
