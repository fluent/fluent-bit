/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2026 The Fluent Bit Authors
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

#ifndef FLB_HTTP_SERVER_CONFIG_H
#define FLB_HTTP_SERVER_CONFIG_H

#include <stddef.h>

#define HTTP_SERVER_INITIAL_BUFFER_SIZE        (10 * 1024)
#define HTTP_SERVER_MAXIMUM_BUFFER_SIZE        (10 * (1000 * 1024))
#define HTTP_SERVER_DEFAULT_IDLE_TIMEOUT       10  /* seconds */

#define FLB_HTTP_SERVER_INGRESS_QUEUE_EVENT_LIMIT 8192
#define FLB_HTTP_SERVER_INGRESS_QUEUE_BYTE_LIMIT  (256 * 1024 * 1024)

struct flb_http_server_config {
    int    http2;
    int    idle_timeout; /* seconds */
    size_t buffer_max_size;
    size_t buffer_chunk_size;
    size_t max_connections;
    int    workers;
    size_t ingress_queue_event_limit;
    size_t ingress_queue_byte_limit;
};

void flb_http_server_config_init(struct flb_http_server_config *config);

#endif
