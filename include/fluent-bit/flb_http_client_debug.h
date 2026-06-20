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

#ifndef FLB_HTTP_CLIENT_DEBUG_H
#define FLB_HTTP_CLIENT_DEBUG_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_callback.h>

static inline void flb_http_client_debug_enable(struct flb_http_client *c,
                                                struct flb_callback *cb_ctx)
{
    c->cb_ctx = cb_ctx;
}

int flb_http_client_debug_setup(struct flb_callback *cb_ctx,
                                struct mk_list *props);
int flb_http_client_debug_cb(struct flb_http_client *c, char *name);

#endif
