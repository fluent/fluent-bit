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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_oauth2_jwt.h>

/*
 * OAuth2 JWT validation needs the native TLS and crypto stack to fetch and
 * verify keys, which the browser build does not have. HTTP inputs reference
 * this interface: it fails closed, so an input configured with
 * 'oauth2.validate' does not start instead of accepting unverified requests.
 */

struct flb_oauth2_jwt_ctx *flb_oauth2_jwt_context_create(struct flb_config *config,
                                                         struct flb_oauth2_jwt_cfg *cfg)
{
    (void) config;
    (void) cfg;

    flb_error("[oauth2_jwt] token validation is not available in the browser build");

    return NULL;
}

void flb_oauth2_jwt_context_destroy(struct flb_oauth2_jwt_ctx *ctx)
{
    (void) ctx;
}

int flb_oauth2_jwt_validate(struct flb_oauth2_jwt_ctx *ctx,
                            const char *authorization_header,
                            size_t authorization_header_len)
{
    (void) ctx;
    (void) authorization_header;
    (void) authorization_header_len;

    return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
}

const char *flb_oauth2_jwt_status_message(int status)
{
    (void) status;

    return "token validation is not available in the browser build";
}
