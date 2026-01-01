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


#ifndef FLB_STD_HTTPREQUEST_H
#define FLB_STD_HTTPREQUEST_H

#include "stackdriver.h"

/* subfield name and size */
#define HTTP_REQUEST_LATENCY "latency"
#define HTTP_REQUEST_PROTOCOL "protocol"
#define HTTP_REQUEST_REFERER "referer"
#define HTTP_REQUEST_REMOTE_IP "remoteIp"
#define HTTP_REQUEST_REQUEST_METHOD "requestMethod"
#define HTTP_REQUEST_REQUEST_URL "requestUrl"
#define HTTP_REQUEST_SERVER_IP "serverIp"
#define HTTP_REQUEST_USER_AGENT "userAgent"
#define HTTP_REQUEST_CACHE_FILL_BYTES "cacheFillBytes"
#define HTTP_REQUEST_REQUESTSIZE "requestSize"
#define HTTP_REQUEST_RESPONSESIZE "responseSize"
#define HTTP_REQUEST_STATUS "status"
#define HTTP_REQUEST_CACHE_HIT "cacheHit"
#define HTTP_REQUEST_CACHE_LOOKUP "cacheLookup"
#define HTTP_REQUEST_CACHE_VALIDATE_WITH_ORIGIN_SERVER "cacheValidatedWithOriginServer"

#define HTTP_REQUEST_LATENCY_SIZE 7
#define HTTP_REQUEST_PROTOCOL_SIZE  8
#define HTTP_REQUEST_REFERER_SIZE 7
#define HTTP_REQUEST_REMOTE_IP_SIZE 8 
#define HTTP_REQUEST_REQUEST_METHOD_SIZE 13
#define HTTP_REQUEST_REQUEST_URL_SIZE 10
#define HTTP_REQUEST_SERVER_IP_SIZE 8
#define HTTP_REQUEST_USER_AGENT_SIZE 9
#define HTTP_REQUEST_CACHE_FILL_BYTES_SIZE 14
#define HTTP_REQUEST_REQUESTSIZE_SIZE 11
#define HTTP_REQUEST_RESPONSESIZE_SIZE 12
#define HTTP_REQUEST_STATUS_SIZE 6
#define HTTP_REQUEST_CACHE_HIT_SIZE 8
#define HTTP_REQUEST_CACHE_LOOKUP_SIZE 11
#define HTTP_REQUEST_CACHE_VALIDATE_WITH_ORIGIN_SERVER_SIZE 30


struct http_request_field {
    flb_sds_t latency;
    flb_sds_t protocol;
    flb_sds_t referer;
    flb_sds_t remoteIp;
    flb_sds_t requestMethod;
    flb_sds_t requestUrl;
    flb_sds_t serverIp;
    flb_sds_t userAgent;

    int64_t cacheFillBytes;
    int64_t requestSize;
    int64_t responseSize;
    int64_t status;

    int cacheHit;
    int cacheLookup;
    int cacheValidatedWithOriginServer;
};

void init_http_request(struct http_request_field *http_request);
void destroy_http_request(struct http_request_field *http_request);

/* 
 *  Add httpRequest field to the entries.
 *  The structure of httpRequest is as shown in struct http_request_field
 */   
void add_http_request_field(struct http_request_field *http_request, 
                            msgpack_packer *mp_pck);

/*
 *  Extract the httpRequest field from the jsonPayload.
 *  If the httpRequest field exists, return TRUE and store the subfields.
 *  If there are extra subfields, count the number.
 */
int extract_http_request(struct http_request_field *http_request,
                         flb_sds_t http_request_key,
                         int http_request_key_size,
                         msgpack_object *obj, int *extra_subfields);

/*
 *  When there are extra subfields, we will preserve the extra subfields inside jsonPayload
 *  For example, if the jsonPayload is as followed：
 *  jsonPayload {
 *      "logging.googleapis.com/http_request": {
 *          "requestMethod": "GET",
 *          "latency": "1s",
 *          "cacheLookup": true,
 *          "extra": "some string"  #extra subfield
 *      }
 *  }
 *  We will preserve the extra subfields. The jsonPayload after extracting is:
 *  jsonPayload {
 *      "logging.googleapis.com/http_request": {
 *          "extra": "some string" 
 *      }
 *  }
 */
void pack_extra_http_request_subfields(msgpack_packer *mp_pck, 
                                       msgpack_object *http_request, 
                                       int extra_subfields);

#endif
