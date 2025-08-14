/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2021-2026 The Fluent Bit Authors
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

#ifndef FLB_AWS_CREDENTIALS_LOG_H

#define FLB_AWS_CREDENTIALS_LOG_H

#include <fluent-bit/flb_log.h>

#define AWS_CREDS_ERROR(format, ...) flb_error("[aws_credentials] " format, ##__VA_ARGS__)
#define AWS_CREDS_WARN(format, ...) flb_warn("[aws_credentials] " format, ##__VA_ARGS__)
#define AWS_CREDS_DEBUG(format, ...) flb_debug("[aws_credentials] " format, ##__VA_ARGS__)

#define AWS_CREDS_ERROR_OR_DEBUG(debug_only, format, ...) do {\
    if (debug_only == FLB_TRUE) {\
        AWS_CREDS_DEBUG(format, ##__VA_ARGS__);\
    }\
    else {\
        AWS_CREDS_ERROR(format, ##__VA_ARGS__);\
    }\
} while (0)

#endif
