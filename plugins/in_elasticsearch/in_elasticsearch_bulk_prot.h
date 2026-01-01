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

#ifndef FLB_IN_ELASTICSEARCH_BULK_PROT
#define FLB_IN_ELASTICSEARCH_BULK_PROT

#include "in_elasticsearch_bulk_conn.h"

#define ES_VERSION_RESPONSE_TEMPLATE \
    "{\"version\":{\"number\":\"%s\",\"build_flavor\":\"Fluent Bit OSS\"},\"tagline\":\"Fluent Bit's Bulk API compatible endpoint\"}"

#define ES_NODES_TEMPLATE "{\"_nodes\":{\"total\":1,\"successful\":1,\"failed\":0}," \
    "\"nodes\":{\"%s\":{\"name\":\"%s\",\"version\":\"8.0.0\"," \
    "\"http\":{\"publish_address\":\"%s:%s\",\"max_content_length_in_bytes\":%ld}}}}"

int in_elasticsearch_bulk_prot_handle(struct flb_in_elasticsearch *ctx,
                                      struct in_elasticsearch_bulk_conn *conn,
                                      struct mk_http_session *session,
                                      struct mk_http_request *request);

int in_elasticsearch_bulk_prot_handle_error(struct flb_in_elasticsearch *ctx,
                                            struct in_elasticsearch_bulk_conn *conn,
                                            struct mk_http_session *session,
                                            struct mk_http_request *request);


int in_elasticsearch_bulk_prot_handle_ng(struct flb_http_request *request,
                                         struct flb_http_response *response);

#endif
