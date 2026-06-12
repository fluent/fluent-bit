/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *  Copyright (C) 2026 Matwey V. Kornilov <matwey.kornilov@gmail.com>
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

#ifndef FLB_IN_AMQP_H
#define FLB_IN_AMQP_H

#include <rabbitmq-c/amqp.h>

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log_event_encoder.h>

struct flb_amqp_connection {
    amqp_connection_state_t conn;
    amqp_socket_t *sock;
    amqp_channel_t chan;
    int coll_id;
};

struct flb_amqp {
    flb_sds_t uri;
    flb_sds_t queue_name;
    flb_sds_t parser_name;
    struct amqp_connection_info conn_info;
    int reconnect_retry_limits;
    int reconnect_retry_interval;

    struct flb_log_event_encoder encoder;
    struct flb_parser *parser;
    struct flb_input_instance *ins;
    int retry_coll_id;
    int retry;

    struct flb_amqp_connection conn;
};

#endif
