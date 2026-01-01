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

#ifndef FLB_IN_COLLECTD_H
#define FLB_IN_COLLECTD_H

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

struct flb_in_collectd_config {
    char *buf;
    int bufsize;

    /* Server */
    char listen[256]; /* RFC-2181 */
    char port[6];     /* RFC-793 */

    /* Sockets */
    flb_sockfd_t server_fd;
    flb_pipefd_t coll_fd;

    flb_sds_t types_db;
    struct mk_list *tdb;
    struct flb_log_event_encoder log_encoder;

    /* Plugin input instance */
    struct flb_input_instance *ins;
};

#endif
