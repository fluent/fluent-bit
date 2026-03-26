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



#ifndef FLB_HS_API_V1_HEALTH_H
#define FLB_HS_API_V1_HEALTH_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_server.h>

struct flb_hs_health_state {
    int healthy;
    int errors;
    int retries_failed;
    int error_limit;
    int retry_failure_limit;
    int period_limit;
};

/* health endpoint*/
int api_v1_health(struct flb_hs *hs);
int flb_hs_health_state_get(struct flb_hs *hs, struct flb_hs_health_state *state);
void read_metrics(void *data, size_t size, int *error_count,
                  int *retry_failure_count);

/* clean up health resource when shutdown*/
void flb_hs_health_destroy();
#endif
