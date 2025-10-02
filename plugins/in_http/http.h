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

#ifndef FLB_IN_HTTP_H
#define FLB_IN_HTTP_H

#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_record_accessor.h>

#include <monkey/monkey.h>
#include <fluent-bit/http_server/flb_http_server.h>

#define HTTP_BUFFER_MAX_SIZE    "4M"
#define HTTP_BUFFER_CHUNK_SIZE  "512K"

struct flb_http {
    int successful_response_code;
    flb_sds_t listen;
    flb_sds_t tcp_port;
    flb_sds_t tag_key;
    struct flb_record_accessor *ra_tag_key;

    /* Success HTTP headers */
    struct mk_list *success_headers;

    struct flb_log_event_encoder log_encoder;

    struct flb_input_instance *ins;

    /* New gen HTTP server */
    int enable_http2;
    struct flb_http_server http_server;

    /* Legacy HTTP server */
    struct flb_downstream *downstream; /* Client manager */
    struct mk_list connections;        /* linked list of connections */

    flb_sds_t success_headers_str;

    size_t buffer_max_size;            /* Maximum buffer size */
    size_t buffer_chunk_size;          /* Chunk allocation size */

    struct mk_server *server;

    int collector_id;
};


#endif
