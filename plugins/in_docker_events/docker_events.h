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

#ifndef FLB_IN_DE_H
#define FLB_IN_DE_H

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_log_event_encoder.h>

#define DEFAULT_BUF_SIZE            8192
#define MIN_BUF_SIZE                2048
#define DEFAULT_FIELD_NAME          "message"
#define DEFAULT_UNIX_SOCKET_PATH    "/var/run/docker.sock"

struct flb_in_de_config
{
    int fd;                         /* File descriptor */
    int coll_id;                    /* collector id */
    flb_sds_t unix_path;            /* Unix path for socket */
    char *buf;
    size_t buf_size;
    flb_sds_t key;

    /* retries */
    int reconnect_retry_limits;
    int reconnect_retry_interval;

    /* retries (internal) */
    int current_retries;
    int retry_coll_id;

    struct flb_parser *parser;
    struct flb_log_event_encoder log_encoder;
    struct flb_input_instance *ins; /* Input plugin instace */

};

#endif
