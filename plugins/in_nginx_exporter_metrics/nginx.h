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

#ifndef FLB_IN_NGINX_H
#define FLB_IN_NGINX_H

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_network.h>

#define DEFAULT_STATUS_URL          "/status"

struct nginx_ctx
{
    int coll_id;                    /* collector id */
    int scrape_interval;            /* collection interval */
    flb_sds_t status_url;
    struct flb_parser *parser;
    struct flb_input_instance *ins; /* Input plugin instace */
    struct flb_upstream *upstream;
    struct cmt *cmt;
    struct cmt_counter *connections_accepted;
    struct cmt_counter *connections_handled;
    struct cmt_counter *connections_total;
    struct cmt_gauge *connection_active;
    struct cmt_gauge *connections_active;
    struct cmt_gauge *connections_reading;
    struct cmt_gauge *connections_writing;
    struct cmt_gauge *connections_waiting;
    struct cmt_gauge *connection_up;
    bool is_up;
    int is_nginx_plus;
    int nginx_plus_version;

    struct nginx_plus_connections *plus_connections;
    struct nginx_plus_http_requests *plus_http_requests;
    struct nginx_plus_ssl *plus_ssl;
    struct nginx_plus_server_zones *server_zones;
    struct nginx_plus_location_zones *location_zones;
    struct nginx_plus_upstreams *upstreams;
    struct nginx_plus_streams *streams;
    struct nginx_plus_stream_upstreams *stream_upstreams;
};

struct nginx_status
{
    uint64_t active;
    uint64_t reading;
    uint64_t writing;
    uint64_t waiting;
    uint64_t accepts;
    uint64_t handled;
    uint64_t requests;
};

struct nginx_plus_connections {
    struct cmt_counter *connections_accepted;
    struct cmt_counter *connections_dropped;
    struct cmt_counter *connections_active;
    struct cmt_counter *connections_idle;
};

struct nginx_plus_ssl {
    struct cmt_counter *handshakes;
    struct cmt_counter *handshakes_failed;
    struct cmt_counter *session_reuses;
};

struct nginx_plus_http_requests {
    struct cmt_counter *total;
    struct cmt_counter *current;
};

struct nginx_plus_server_zones {
    struct cmt_counter *discarded;
    struct cmt_counter *processing;
    struct cmt_counter *received;
    struct cmt_counter *requests;
    struct cmt_counter *responses;
    struct cmt_counter *sent;
};

struct nginx_plus_upstreams {
    //struct nginx_plux_upstream_peer **peers;
    struct cmt_gauge   *keepalives;
    struct cmt_gauge   *zombies;
    // per peer
    struct cmt_gauge   *active;
    struct cmt_counter *fails;
    struct cmt_gauge   *header_time;
    struct cmt_gauge   *limit;
    struct cmt_counter *received;
    struct cmt_counter *requests;
    struct cmt_counter *responses;
    struct cmt_gauge   *response_time;
    struct cmt_counter *sent;
    struct cmt_gauge   *state;
    struct cmt_counter *unavail;
};

struct nginx_plus_location_zones {
    struct cmt_counter *discarded;
    struct cmt_counter *received;
    struct cmt_counter *requests;
    struct cmt_counter *responses;
    struct cmt_counter *sent;
};

struct nginx_plus_streams {
    struct cmt_counter *connections;
    struct cmt_counter *discarded;
    struct cmt_counter *processing;
    struct cmt_counter *received;
    struct cmt_counter *sent;
    struct cmt_counter *sessions;
};

struct nginx_plus_stream_upstreams {
    struct cmt_gauge   *zombies;
    // per peer
    struct cmt_gauge   *active;
    struct cmt_counter *fails;
    struct cmt_gauge   *limit;
    struct cmt_counter *received;
    struct cmt_gauge   *connect_time;
    struct cmt_gauge   *first_byte_time;
    struct cmt_counter *connections;
    struct cmt_gauge   *response_time;
    struct cmt_counter *sent;
    struct cmt_gauge   *state;
    struct cmt_counter *unavail;
};

#endif