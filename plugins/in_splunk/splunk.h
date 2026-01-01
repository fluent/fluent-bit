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

#ifndef FLB_IN_SPLUNK_H
#define FLB_IN_SPLUNK_H

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

struct flb_splunk_tokens {
    flb_sds_t header;
    size_t    length;
    struct mk_list _head;
};

struct flb_splunk {
    flb_sds_t listen;
    flb_sds_t tcp_port;
    flb_sds_t tag_key;
    struct flb_record_accessor *ra_tag_key;

    /* Success HTTP headers */
    struct mk_list *success_headers;

    /* Token Auth */
    struct mk_list auth_tokens;
    flb_sds_t ingested_auth_header;
    size_t ingested_auth_header_len;
    int store_token_in_metadata;
    flb_sds_t store_token_key;

    struct flb_log_event_encoder log_encoder;

    struct flb_input_instance *ins;

    /* New gen HTTP server */
    int enable_http2;
    struct flb_http_server http_server;

    /* Legacy HTTP server */
    flb_sds_t success_headers_str;
    int collector_id;
    size_t buffer_max_size;            /* Maximum buffer size */
    size_t buffer_chunk_size;          /* Chunk allocation size */
    struct flb_downstream *downstream; /* Client manager */
    struct mk_list connections;        /* linked list of connections */
    struct mk_server *server;
};


#endif
