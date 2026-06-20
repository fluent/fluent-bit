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
#include <fluent-bit/flb_regex.h>
#include "stackdriver.h"
#include "stackdriver_helper.h"
#include "stackdriver_http_request.h"

#include <ctype.h>

typedef enum {
    NO_HTTPREQUEST = 1,
    HTTPREQUEST_EXISTS = 2
} http_request_status;

void init_http_request(struct http_request_field *http_request)
{
    http_request->latency = flb_sds_create("");
    http_request->protocol = flb_sds_create("");
    http_request->referer = flb_sds_create("");
    http_request->remoteIp = flb_sds_create("");
    http_request->requestMethod = flb_sds_create("");
    http_request->requestUrl = flb_sds_create("");
    http_request->serverIp = flb_sds_create("");
    http_request->userAgent = flb_sds_create("");

    http_request->cacheFillBytes = 0;
    http_request->requestSize = 0;
    http_request->responseSize = 0;
    http_request->status = 0;

    http_request->cacheHit = FLB_FALSE;
    http_request->cacheLookup = FLB_FALSE;
    http_request->cacheValidatedWithOriginServer = FLB_FALSE;
}

void destroy_http_request(struct http_request_field *http_request)
{
    flb_sds_destroy(http_request->latency);
    flb_sds_destroy(http_request->protocol);
    flb_sds_destroy(http_request->referer);
    flb_sds_destroy(http_request->remoteIp);
    flb_sds_destroy(http_request->requestMethod);
    flb_sds_destroy(http_request->requestUrl);
    flb_sds_destroy(http_request->serverIp);
    flb_sds_destroy(http_request->userAgent);
}

void add_http_request_field(struct http_request_field *http_request,
                            msgpack_packer *mp_pck)
{
    msgpack_pack_str(mp_pck, 11);
    msgpack_pack_str_body(mp_pck, "httpRequest", 11);

    if (flb_sds_is_empty(http_request->latency) == FLB_TRUE) {
        msgpack_pack_map(mp_pck, 14);
    }
    else {
        msgpack_pack_map(mp_pck, 15);

        msgpack_pack_str(mp_pck, HTTP_REQUEST_LATENCY_SIZE);
        msgpack_pack_str_body(mp_pck, HTTP_REQUEST_LATENCY,
                              HTTP_REQUEST_LATENCY_SIZE);
        msgpack_pack_str(mp_pck, flb_sds_len(http_request->latency));
        msgpack_pack_str_body(mp_pck, http_request->latency,
                              flb_sds_len(http_request->latency));
    }

    /* String sub-fields */
    msgpack_pack_str(mp_pck, HTTP_REQUEST_REQUEST_METHOD_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_REQUEST_METHOD,
                          HTTP_REQUEST_REQUEST_METHOD_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(http_request->requestMethod));
    msgpack_pack_str_body(mp_pck, http_request->requestMethod,
                          flb_sds_len(http_request->requestMethod));

    msgpack_pack_str(mp_pck, HTTP_REQUEST_REQUEST_URL_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_REQUEST_URL,
                          HTTP_REQUEST_REQUEST_URL_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(http_request->requestUrl));
    msgpack_pack_str_body(mp_pck, http_request->requestUrl,
                          flb_sds_len(http_request->requestUrl));

    msgpack_pack_str(mp_pck, HTTP_REQUEST_USER_AGENT_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_USER_AGENT,
                          HTTP_REQUEST_USER_AGENT_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(http_request->userAgent));
    msgpack_pack_str_body(mp_pck, http_request->userAgent,
                          flb_sds_len(http_request->userAgent));

    msgpack_pack_str(mp_pck, HTTP_REQUEST_REMOTE_IP_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_REMOTE_IP,
                          HTTP_REQUEST_REMOTE_IP_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(http_request->remoteIp));
    msgpack_pack_str_body(mp_pck, http_request->remoteIp,
                          flb_sds_len(http_request->remoteIp));

    msgpack_pack_str(mp_pck, HTTP_REQUEST_SERVER_IP_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_SERVER_IP,
                          HTTP_REQUEST_SERVER_IP_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(http_request->serverIp));
    msgpack_pack_str_body(mp_pck, http_request->serverIp,
                          flb_sds_len(http_request->serverIp));

    msgpack_pack_str(mp_pck, HTTP_REQUEST_REFERER_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_REFERER,
                          HTTP_REQUEST_REFERER_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(http_request->referer));
    msgpack_pack_str_body(mp_pck, http_request->referer,
                          flb_sds_len(http_request->referer));

    msgpack_pack_str(mp_pck, HTTP_REQUEST_PROTOCOL_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_PROTOCOL,
                          HTTP_REQUEST_PROTOCOL_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(http_request->protocol));
    msgpack_pack_str_body(mp_pck, http_request->protocol,
                          flb_sds_len(http_request->protocol));

    /* Integer sub-fields */
    msgpack_pack_str(mp_pck, HTTP_REQUEST_REQUESTSIZE_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_REQUESTSIZE,
                          HTTP_REQUEST_REQUESTSIZE_SIZE);
    msgpack_pack_int64(mp_pck, http_request->requestSize);

    msgpack_pack_str(mp_pck, HTTP_REQUEST_RESPONSESIZE_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_RESPONSESIZE,
                          HTTP_REQUEST_RESPONSESIZE_SIZE);
    msgpack_pack_int64(mp_pck, http_request->responseSize);

    msgpack_pack_str(mp_pck, HTTP_REQUEST_STATUS_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_STATUS, HTTP_REQUEST_STATUS_SIZE);
    msgpack_pack_int64(mp_pck, http_request->status);

    msgpack_pack_str(mp_pck, HTTP_REQUEST_CACHE_FILL_BYTES_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_CACHE_FILL_BYTES,
                          HTTP_REQUEST_CACHE_FILL_BYTES_SIZE);
    msgpack_pack_int64(mp_pck, http_request->cacheFillBytes);

    /* Boolean sub-fields */
    msgpack_pack_str(mp_pck, HTTP_REQUEST_CACHE_LOOKUP_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_CACHE_LOOKUP,
                          HTTP_REQUEST_CACHE_LOOKUP_SIZE);
    if (http_request->cacheLookup == FLB_TRUE) {
        msgpack_pack_true(mp_pck);
    }
    else {
        msgpack_pack_false(mp_pck);
    }

    msgpack_pack_str(mp_pck, HTTP_REQUEST_CACHE_HIT_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_CACHE_HIT,
                          HTTP_REQUEST_CACHE_HIT_SIZE);
    if (http_request->cacheLookup == FLB_TRUE) {
        msgpack_pack_true(mp_pck);
    }
    else {
        msgpack_pack_false(mp_pck);
    }

    msgpack_pack_str(mp_pck, HTTP_REQUEST_CACHE_VALIDATE_WITH_ORIGIN_SERVER_SIZE);
    msgpack_pack_str_body(mp_pck, HTTP_REQUEST_CACHE_VALIDATE_WITH_ORIGIN_SERVER,
                          HTTP_REQUEST_CACHE_VALIDATE_WITH_ORIGIN_SERVER_SIZE);
    if (http_request->cacheValidatedWithOriginServer == FLB_TRUE) {
        msgpack_pack_true(mp_pck);
    }
    else {
        msgpack_pack_false(mp_pck);
    }
}

/* latency should be in the format:
 *      whitespace (opt.) + integer + point & decimal (opt.)
 *      + whitespace (opt.) + "s" + whitespace (opt.)
 *
 * latency is Duration, so the maximum value is "315576000000.999999999s".
 * (23 characters in length)
 */
static void validate_latency(msgpack_object_str latency_in_payload,
                             struct http_request_field *http_request) {
    int i = 0;
    int j = 0;
    int status = 0;
    char extract_latency[32];
    flb_sds_t pattern;
    struct flb_regex *regex;

    pattern = flb_sds_create("^\\s*\\d+(.\\d+)?\\s*s\\s*$");
    if (!pattern) {
        return;
    }

    if (latency_in_payload.size > sizeof(extract_latency)) {
        flb_sds_destroy(pattern);
        return;
    }

    regex = flb_regex_create(pattern);
    status = flb_regex_match(regex,
                             (unsigned char *) latency_in_payload.ptr,
                             latency_in_payload.size);
    flb_regex_destroy(regex);
    flb_sds_destroy(pattern);

    if (status == 1) {
        for (; i < latency_in_payload.size; ++ i) {
            if (latency_in_payload.ptr[i] == '.' || latency_in_payload.ptr[i] == 's'
                || isdigit(latency_in_payload.ptr[i])) {
                extract_latency[j] = latency_in_payload.ptr[i];
                ++ j;
            }
        }
        http_request->latency = flb_sds_copy(http_request->latency, extract_latency, j);
    }
}

/* Return true if httpRequest extracted */
int extract_http_request(struct http_request_field *http_request,
                         flb_sds_t http_request_key,
                         int http_request_key_size,
                         msgpack_object *obj, int *extra_subfields)
{
    http_request_status op_status = NO_HTTPREQUEST;
    msgpack_object_kv *p;
    msgpack_object_kv *pend;
    msgpack_object_kv *tmp_p;
    msgpack_object_kv *tmp_pend;

    if (obj->via.map.size == 0) {
        return FLB_FALSE;
    }

    p = obj->via.map.ptr;
    pend = obj->via.map.ptr + obj->via.map.size;

    for (; p < pend && op_status == NO_HTTPREQUEST; ++p) {

        if (p->val.type != MSGPACK_OBJECT_MAP
            || !validate_key(p->key, http_request_key,
                             http_request_key_size)) {

            continue;
        }

        op_status = HTTPREQUEST_EXISTS;
        msgpack_object sub_field = p->val;

        tmp_p = sub_field.via.map.ptr;
        tmp_pend = sub_field.via.map.ptr + sub_field.via.map.size;

        /* Validate the subfields of httpRequest */
        for (; tmp_p < tmp_pend; ++tmp_p) {
            if (tmp_p->key.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (validate_key(tmp_p->key, HTTP_REQUEST_LATENCY,
                             HTTP_REQUEST_LATENCY_SIZE)) {
                if (tmp_p->val.type != MSGPACK_OBJECT_STR) {
                    continue;
                }
                validate_latency(tmp_p->val.via.str, http_request);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_PROTOCOL,
                                  HTTP_REQUEST_PROTOCOL_SIZE)) {
                try_assign_subfield_str(tmp_p->val, &http_request->protocol);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_REFERER,
                                  HTTP_REQUEST_REFERER_SIZE)) {
                try_assign_subfield_str(tmp_p->val, &http_request->referer);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_REMOTE_IP,
                                  HTTP_REQUEST_REMOTE_IP_SIZE)) {
                try_assign_subfield_str(tmp_p->val, &http_request->remoteIp);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_REQUEST_METHOD,
                                  HTTP_REQUEST_REQUEST_METHOD_SIZE)) {
                try_assign_subfield_str(tmp_p->val, &http_request->requestMethod);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_REQUEST_URL,
                                  HTTP_REQUEST_REQUEST_URL_SIZE)) {
                try_assign_subfield_str(tmp_p->val, &http_request->requestUrl);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_SERVER_IP,
                                  HTTP_REQUEST_SERVER_IP_SIZE)) {
                try_assign_subfield_str(tmp_p->val, &http_request->serverIp);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_USER_AGENT,
                                  HTTP_REQUEST_USER_AGENT_SIZE)) {
                try_assign_subfield_str(tmp_p->val, &http_request->userAgent);
            }

            else if (validate_key(tmp_p->key, HTTP_REQUEST_CACHE_FILL_BYTES,
                                  HTTP_REQUEST_CACHE_FILL_BYTES_SIZE)) {
                try_assign_subfield_int(tmp_p->val, &http_request->cacheFillBytes);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_REQUESTSIZE,
                                  HTTP_REQUEST_REQUESTSIZE_SIZE)) {
                try_assign_subfield_int(tmp_p->val, &http_request->requestSize);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_RESPONSESIZE,
                                  HTTP_REQUEST_RESPONSESIZE_SIZE)) {
                try_assign_subfield_int(tmp_p->val, &http_request->responseSize);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_STATUS,
                                  HTTP_REQUEST_STATUS_SIZE)) {
                try_assign_subfield_int(tmp_p->val, &http_request->status);
            }

            else if (validate_key(tmp_p->key, HTTP_REQUEST_CACHE_HIT,
                                  HTTP_REQUEST_CACHE_HIT_SIZE)) {
                try_assign_subfield_bool(tmp_p->val, &http_request->cacheHit);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_CACHE_LOOKUP,
                                  HTTP_REQUEST_CACHE_LOOKUP_SIZE)) {
                try_assign_subfield_bool(tmp_p->val, &http_request->cacheLookup);
            }
            else if (validate_key(tmp_p->key, HTTP_REQUEST_CACHE_VALIDATE_WITH_ORIGIN_SERVER,
                                  HTTP_REQUEST_CACHE_VALIDATE_WITH_ORIGIN_SERVER_SIZE)) {
                try_assign_subfield_bool(tmp_p->val,
                                         &http_request->cacheValidatedWithOriginServer);
            }

            else {
                *extra_subfields += 1;
            }
        }
    }

    return op_status == HTTPREQUEST_EXISTS;
}

void pack_extra_http_request_subfields(msgpack_packer *mp_pck,
                                       msgpack_object *http_request,
                                       int extra_subfields) {
    msgpack_object_kv *p = http_request->via.map.ptr;
    msgpack_object_kv *const pend = http_request->via.map.ptr + http_request->via.map.size;

    msgpack_pack_map(mp_pck, extra_subfields);

    for (; p < pend; ++p) {
        if (validate_key(p->key, HTTP_REQUEST_LATENCY,
                         HTTP_REQUEST_LATENCY_SIZE)
            || validate_key(p->key, HTTP_REQUEST_PROTOCOL,
                            HTTP_REQUEST_PROTOCOL_SIZE)
            || validate_key(p->key, HTTP_REQUEST_REFERER,
                            HTTP_REQUEST_REFERER_SIZE)
            || validate_key(p->key, HTTP_REQUEST_REMOTE_IP,
                            HTTP_REQUEST_REMOTE_IP_SIZE)
            || validate_key(p->key, HTTP_REQUEST_REQUEST_METHOD,
                            HTTP_REQUEST_REQUEST_METHOD_SIZE)
            || validate_key(p->key, HTTP_REQUEST_REQUEST_URL,
                            HTTP_REQUEST_REQUEST_URL_SIZE)
            || validate_key(p->key, HTTP_REQUEST_SERVER_IP,
                            HTTP_REQUEST_SERVER_IP_SIZE)
            || validate_key(p->key, HTTP_REQUEST_USER_AGENT,
                            HTTP_REQUEST_USER_AGENT_SIZE)
            || validate_key(p->key, HTTP_REQUEST_CACHE_FILL_BYTES,
                            HTTP_REQUEST_CACHE_FILL_BYTES_SIZE)
            || validate_key(p->key, HTTP_REQUEST_REQUESTSIZE,
                            HTTP_REQUEST_REQUESTSIZE_SIZE)
            || validate_key(p->key, HTTP_REQUEST_RESPONSESIZE,
                            HTTP_REQUEST_RESPONSESIZE_SIZE)
            || validate_key(p->key, HTTP_REQUEST_STATUS,
                            HTTP_REQUEST_STATUS_SIZE)
            || validate_key(p->key, HTTP_REQUEST_CACHE_HIT,
                            HTTP_REQUEST_CACHE_HIT_SIZE)
            || validate_key(p->key, HTTP_REQUEST_CACHE_LOOKUP,
                            HTTP_REQUEST_CACHE_LOOKUP_SIZE)
            || validate_key(p->key, HTTP_REQUEST_CACHE_VALIDATE_WITH_ORIGIN_SERVER,
                            HTTP_REQUEST_CACHE_VALIDATE_WITH_ORIGIN_SERVER_SIZE)) {

            continue;
        }

        msgpack_pack_object(mp_pck, p->key);
        msgpack_pack_object(mp_pck, p->val);
    }
}
