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

#ifndef FLB_IN_PROM_RW_PROT
#define FLB_IN_PROM_RW_PROT

#include <fluent-bit/flb_http_common.h>

int prom_rw_prot_handle(struct flb_prom_remote_write *ctx,
                        struct prom_remote_write_conn *conn,
                        struct mk_http_session *session,
                        struct mk_http_request *request);

int prom_rw_prot_handle_error(struct flb_prom_remote_write *ctx,
                              struct prom_remote_write_conn *conn,
                              struct mk_http_session *session,
                              struct mk_http_request *request);


int prom_rw_prot_handle_ng(struct flb_http_request *request,
                           struct flb_http_response *response);

#endif
