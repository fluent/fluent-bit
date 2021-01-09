/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_thread_storage.h>
#include <fluent-bit/flb_coro.h>

FLB_TLS_DEFINE(struct flb_coro, flb_coro_key);

void flb_coro_init()
{
    FLB_TLS_INIT(flb_coro_key);
}

struct flb_coro *flb_coro_get()
{
    struct flb_coro *coro;

    coro = FLB_TLS_GET(flb_coro_key);
    return coro;
}

void flb_coro_set(struct flb_coro *coro)
{
    FLB_TLS_SET(flb_coro_key, coro);
}
