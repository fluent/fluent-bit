/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_IN_NS_H
#define FLB_IN_NS_H

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_parser.h>

#define DEFAULT_BUF_SIZE            8192
#define MIN_BUF_SIZE                2048
#define DEFAULT_FIELD_NAME          "message"

struct flb_in_ns_config
{
    int coll_id;                    /* collector id */
    char *host;
    int port;
    struct flb_parser *parser;
    struct flb_input_instance *ins; /* Input plugin instace */
};

struct flb_in_ns_status
{
    int active;
    int reading;
    int writing;
    int waiting;
    int accepts;
    int handled;
    int requests;
};

#endif
