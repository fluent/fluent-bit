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

#ifndef FLB_IN_SPLUNK_PROT
#define FLB_IN_SPLUNK_PROT

#define SPLUNK_AUTH_UNAUTH        1
#define SPLUNK_AUTH_SUCCESS       0
#define SPLUNK_AUTH_MISSING_CRED -1
#define SPLUNK_AUTH_UNAUTHORIZED -2

#include <fluent-bit/flb_http_common.h>

int splunk_prot_handle(struct flb_splunk *ctx, struct splunk_conn *conn,
                       struct mk_http_session *session,
                       struct mk_http_request *request);

int splunk_prot_handle_error(struct flb_splunk *ctx, struct splunk_conn *conn,
                             struct mk_http_session *session,
                             struct mk_http_request *request);

int splunk_prot_handle_ng(struct flb_http_request *request,
                          struct flb_http_response *response);

#endif
