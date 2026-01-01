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

#ifndef FLB_OUT_WS
#define FLB_OUT_WS

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>

/*
 * Configuration: we put this separate from the main
 * context so every Upstream Node can have it own configuration
 * reference and pass it smoothly to the required caller.
 *
 * On simple mode (no HA), the structure is referenced
 * by flb_forward->config. In HA mode the structure is referenced
 * by the Upstream node context as an opaque data type.
 */
struct flb_out_ws {
    int out_format;
    char *uri;
    char *host;
    int port;
    /* Timestamp format */
    int json_date_format;
    
    flb_sds_t json_date_key;
    size_t buffer_size;
    struct flb_upstream *u;
    int handshake;
    time_t last_input_timestamp;
    int idle_interval;

    /* Arbitrary HTTP headers */
    struct mk_list *headers;

    /* Plugin instance */
    struct flb_output_instance *ins;
};

#endif
