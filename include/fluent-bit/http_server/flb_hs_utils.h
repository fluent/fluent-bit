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

#ifndef FLB_HS_UTIL_H
#define FLB_HS_UTIL_H

#include <monkey/mk_lib.h>

int flb_hs_add_content_type_to_req(mk_request_t *request, int type);

/* Content-type */
enum content_type {
    FLB_HS_CONTENT_TYPE_JSON,
    FLB_HS_CONTENT_TYPE_PROMETHEUS,
    FLB_HS_CONTENT_TYPE_OTHER
};

#define FLB_HS_CONTENT_TYPE_KEY_STR "Content-Type"
#define FLB_HS_CONTENT_TYPE_KEY_LEN 12

#define FLB_HS_CONTENT_TYPE_JSON_STR  "application/json"
#define FLB_HS_CONTENT_TYPE_JSON_LEN  16
#define FLB_HS_CONTENT_TYPE_PROMETHEUS_STR "text/plain; version=0.0.4"
#define FLB_HS_CONTENT_TYPE_PROMETHEUS_LEN 25

#endif
