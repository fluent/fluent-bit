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

#include <fluent-bit/flb_log.h>
#include <fluent-bit/http_server/flb_hs_utils.h>
#include <string.h>

int flb_hs_add_content_type_to_req(mk_request_t *request, int type)
{
    if (request == NULL) {
        return -1;
    }

    switch (type) {
    case FLB_HS_CONTENT_TYPE_JSON:
        mk_http_header(request,
                       FLB_HS_CONTENT_TYPE_KEY_STR, FLB_HS_CONTENT_TYPE_KEY_LEN,
                       FLB_HS_CONTENT_TYPE_JSON_STR, FLB_HS_CONTENT_TYPE_JSON_LEN);
        break;
    case FLB_HS_CONTENT_TYPE_PROMETHEUS:
        mk_http_header(request,
                       FLB_HS_CONTENT_TYPE_KEY_STR, FLB_HS_CONTENT_TYPE_KEY_LEN,
                       FLB_HS_CONTENT_TYPE_PROMETHEUS_STR, FLB_HS_CONTENT_TYPE_PROMETHEUS_LEN);
        break;
    case FLB_HS_CONTENT_TYPE_OTHER:
        break;
    default:
        flb_error("[%s] unknown type=%d", __FUNCTION__, type);
        return -1;
    }

    return 0;
}

int flb_hs_response_set_content_type(struct flb_http_response *response, int type)
{
    if (response == NULL) {
        return -1;
    }

    switch (type) {
    case FLB_HS_CONTENT_TYPE_JSON:
        flb_http_response_set_header(response,
                                     FLB_HS_CONTENT_TYPE_KEY_STR, FLB_HS_CONTENT_TYPE_KEY_LEN,
                                     FLB_HS_CONTENT_TYPE_JSON_STR, FLB_HS_CONTENT_TYPE_JSON_LEN);
        break;
    case FLB_HS_CONTENT_TYPE_PROMETHEUS:
        flb_http_response_set_header(response,
                                     FLB_HS_CONTENT_TYPE_KEY_STR, FLB_HS_CONTENT_TYPE_KEY_LEN,
                                     FLB_HS_CONTENT_TYPE_PROMETHEUS_STR, FLB_HS_CONTENT_TYPE_PROMETHEUS_LEN);
        break;
    case FLB_HS_CONTENT_TYPE_OTHER:
        break;
    default:
        flb_error("[%s] unknown type=%d", __FUNCTION__, type);
        return -1;
    }

    return 0;
}

int flb_hs_response_set_payload(struct flb_http_response *response,
                                int status,
                                int type,
                                const void *payload,
                                size_t payload_size)
{
    if (response == NULL) {
        return -1;
    }

    flb_http_response_set_status(response, status);
    flb_hs_response_set_content_type(response, type);

    if (payload != NULL && payload_size > 0) {
        flb_http_response_set_body(response, (unsigned char *) payload, payload_size);
    }
    else {
        flb_http_response_set_body(response, NULL, 0);
    }

    return flb_http_response_commit(response);
}

int flb_hs_response_send_string(struct flb_http_response *response,
                                int status,
                                int type,
                                const char *payload)
{
    size_t payload_size;

    if (payload == NULL) {
        payload_size = 0;
    }
    else {
        payload_size = strlen(payload);
    }

    return flb_hs_response_set_payload(response, status, type, payload, payload_size);
}
