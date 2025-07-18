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

#ifndef FLB_IN_TCP_H
#define FLB_IN_TCP_H

#define FLB_TCP_FMT_JSON    0  /* default */
#define FLB_TCP_FMT_NONE    1  /* no format, use delimiters */

#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

struct flb_in_tcp_config {
    flb_sds_t format_name;             /* Data format name */
    int format;                        /* Data format */
    size_t buffer_size;                /* Buffer size for each reader */
    flb_sds_t buffer_size_str;         /* Buffer size in string form  */
    size_t chunk_size;                 /* Chunk allocation size       */
    flb_sds_t chunk_size_str;          /* Chunk size in string form   */
    char *listen;                      /* Listen interface            */
    char *tcp_port;                    /* TCP Port                    */
    flb_sds_t raw_separator;           /* Unescaped string delimiterr */
    flb_sds_t separator;               /* String delimiter            */
    flb_sds_t source_address_key;      /* Source IP address           */
    int collector_id;                  /* Listener collector id       */
    struct flb_downstream *downstream; /* Client manager */
    struct mk_list connections;        /* List of active connections  */
    struct flb_input_instance *ins;    /* Input plugin instace        */
    struct flb_log_event_encoder *log_encoder;
    int is_paused;                     /* Plugin is paused            */
};

#endif
