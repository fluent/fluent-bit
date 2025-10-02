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

#ifndef FLB_IN_ELASTICSEARCH_H
#define FLB_IN_ELASTICSEARCH_H

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

struct flb_in_elasticsearch {
    flb_sds_t listen;
    flb_sds_t tcp_port;
    flb_sds_t tag_key;
    flb_sds_t meta_key;
    flb_sds_t hostname;
    flb_sds_t es_version;
    char cluster_name[16];
    char node_name[12];

    struct flb_log_event_encoder *log_encoder;
    struct flb_record_accessor *ra_tag_key;

    struct flb_input_instance *ins;

    /* New gen HTTP server */
    int enable_http2;
    struct flb_http_server http_server;

    /* Legacy HTTP server */
    int collector_id;

    size_t buffer_max_size;            /* Maximum buffer size */
    size_t buffer_chunk_size;          /* Chunk allocation size */

    struct flb_downstream *downstream; /* Client manager */
    struct mk_list connections;        /* linked list of connections */

    struct mk_server *server;
};


#endif
