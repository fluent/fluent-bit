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
#include <fluent-bit/flb_http_server.h>

#include "uptime.h"
#include "metrics.h"
#include "storage.h"
#include "plugins.h"
#include "health.h"
#include "trace.h"

int api_v1_registration(struct flb_hs *hs)
{
    api_v1_uptime(hs);
    api_v1_metrics(hs);
    api_v1_plugins(hs);

#ifdef FLB_HAVE_CHUNK_TRACE
    api_v1_trace(hs);
#endif /* FLB_HAVE_CHUNK_TRACE */

    if (hs->config->health_check == FLB_TRUE) {
        api_v1_health(hs);
    }

    if (hs->config->storage_metrics == FLB_TRUE) {
        api_v1_storage_metrics(hs);
    }

    return 0;
}
