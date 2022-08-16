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

#ifndef FLB_IN_HTTP_H
#define FLB_IN_HTTP_H

#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_regex.h>

#include <monkey/monkey.h>

#define HTTP_BUFFER_MAX_SIZE    "4M"
#define HTTP_BUFFER_CHUNK_SIZE  "512K"

struct flb_http {
    int successful_response_code;
    flb_sds_t listen;
    flb_sds_t tcp_port;
    const char *tag_key;

    int collector_id;

    size_t buffer_max_size;            /* Maximum buffer size */
    size_t buffer_chunk_size;          /* Chunk allocation size */

    struct flb_downstream *downstream; /* Client manager */
    struct mk_list connections;        /* linked list of connections */
    struct mk_event_loop *evl;         /* Event loop context */

    struct mk_list *add_headers_map;    /* config_map to append header value */
    struct mk_list add_headers;
    int add_headers_num;

    struct mk_server *server;
    struct flb_input_instance *ins;
};

struct header_key_condition {
    struct flb_regex *regex;
    struct mk_list _head;
};


#endif
