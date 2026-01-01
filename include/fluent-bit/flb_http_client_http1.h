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

#ifndef FLB_HTTP_CLIENT_HTTP1_H
#define FLB_HTTP_CLIENT_HTTP1_H

#include <fluent-bit/flb_http_common.h>

struct flb_http_client;
struct flb_http_client_session;

struct flb_http1_client_session {
    struct flb_http_client         *inner_session;
    int                             initialized;
    struct flb_http_client_session *parent;
};

int flb_http1_client_session_init(struct flb_http1_client_session *session);

void flb_http1_client_session_destroy(struct flb_http1_client_session *session);

int flb_http1_client_session_ingest(struct flb_http1_client_session *session,
                                    unsigned char *buffer,
                                    size_t length);

int flb_http1_request_begin(struct flb_http_request *request);

int flb_http1_request_commit(struct flb_http_request *request);

#endif
