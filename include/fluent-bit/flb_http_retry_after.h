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

#ifndef FLB_HTTP_RETRY_AFTER_H
#define FLB_HTTP_RETRY_AFTER_H

#include <fluent-bit/flb_macros.h>

#include <stddef.h>
#include <stdint.h>

enum flb_retry_after_status {
    FLB_RETRY_AFTER_ABSENT = 0,
    FLB_RETRY_AFTER_VALID,
    FLB_RETRY_AFTER_INVALID,
    FLB_RETRY_AFTER_SATURATED
};

FLB_EXPORT int flb_http_retry_after_parse(const char *value,
                                          size_t length,
                                          int64_t received_wall_time_ms,
                                          uint64_t *delay_ms);

FLB_EXPORT int flb_http_retry_after_parse_headers(const char *headers,
                                                  size_t length,
                                                  int64_t received_wall_time_ms,
                                                  uint64_t *delay_ms,
                                                  size_t *invalid_count);

#endif
