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

#include<stdio.h>
#include <stdlib.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/http_server/flb_hs_utils.h>
#include <msgpack.h>

#include "health.h"

/*
* tell what's the current status for health check
* One default background is that the metrics received and saved into
* message queue every time is a accumulation of error numbers,
* not a error number in recent second. So to get the error number
* in a period, we need to use:
* the error number of the newest metrics message  minus
* the error number in oldest metrics of period
*/
int flb_hs_health_state_get(struct flb_hs *hs, struct flb_hs_health_state *state)
{
    struct flb_hs_hc_buf *buf;

    if (hs == NULL || state == NULL) {
        return -1;
    }

    memset(state, 0, sizeof(struct flb_hs_health_state));
    state->error_limit = hs->health_counter.error_limit;
    state->retry_failure_limit = hs->health_counter.retry_failure_limit;
    state->period_limit = hs->health_counter.period_limit;

    if (mk_list_is_empty(&hs->health_metrics) == 0) {
        state->healthy = FLB_TRUE;
        return 0;
    }

    /* Get the error metrics entry from the start time of current period */
    buf = mk_list_entry_first(&hs->health_metrics, struct flb_hs_hc_buf, _head);

    /*
    * increase user so clean up function won't
    * free the memory and delete the data
    */
    buf->users++;

    /* the error count saved in message queue is the number of
    * error count at that time. So the math is that:
    * the error count in current period = (current error count in total) -
    * (begin error count in the period)
    */
    state->errors = hs->health_counter.error_counter -  buf->error_count;
    state->retries_failed = hs->health_counter.retry_failure_counter -
                            buf->retry_failure_count;
    buf->users--;

    if (state->errors > hs->health_counter.error_limit ||
        state->retries_failed > hs->health_counter.retry_failure_limit) {
        state->healthy = FLB_FALSE;
        return 0;
    }

    state->healthy = FLB_TRUE;

    return 0;
}

/* read the metrics from message queue and update the counter*/
void read_metrics(void *data, size_t size, int* error_count,
                  int* retry_failure_count)
{
    int i;
    int j;
    int m;
    msgpack_unpacked result;
    msgpack_object map;
    size_t off = 0;
    int errors = 0;
    int retry_failure = 0;

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, data, size, &off);
    map = result.data;

    for (i = 0; i < map.via.map.size; i++) {
        msgpack_object k;
        msgpack_object v;

        /* Keys: input, output */
        k = map.via.map.ptr[i].key;
        v = map.via.map.ptr[i].val;
        if (k.via.str.size != sizeof("output") - 1 ||
            strncmp(k.via.str.ptr, "output", k.via.str.size) != 0) {

            continue;
        }
        /* Iterate sub-map */
        for (j = 0; j < v.via.map.size; j++) {
            msgpack_object sv;

            /* Keys: plugin name , values: metrics */
            sv = v.via.map.ptr[j].val;

            for (m = 0; m < sv.via.map.size; m++) {
                msgpack_object mk;
                msgpack_object mv;

                mk = sv.via.map.ptr[m].key;
                mv = sv.via.map.ptr[m].val;

                if (mk.via.str.size == sizeof("errors") - 1 &&
                    strncmp(mk.via.str.ptr, "errors", mk.via.str.size) == 0) {
                    errors += mv.via.u64;
                }
                else if (mk.via.str.size == sizeof("retries_failed") - 1 &&
                    strncmp(mk.via.str.ptr, "retries_failed",
                            mk.via.str.size) == 0) {
                    retry_failure += mv.via.u64;
                }
            }
        }
    }

    *error_count = errors;
    *retry_failure_count = retry_failure;
    msgpack_unpacked_destroy(&result);
}

/* API: Get fluent Bit Health Status */
static int cb_health(struct flb_hs *hs,
                     struct flb_http_request *request,
                     struct flb_http_response *response)
{
    int ret;
    struct flb_hs_health_state state;

    (void) request;

    if (flb_hs_health_state_get(hs, &state) != 0) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    if (state.healthy == FLB_TRUE) {
       ret = flb_hs_response_send_string(response, 200,
                                         FLB_HS_CONTENT_TYPE_OTHER, "ok\n");
    }
    else {
        ret = flb_hs_response_send_string(response, 500,
                                          FLB_HS_CONTENT_TYPE_OTHER, "error\n");
    }

    return ret;
}

/* Perform registration */
int api_v1_health(struct flb_hs *hs)
{
    return flb_hs_register_endpoint(hs, "/api/v1/health",
                                    FLB_HS_ROUTE_EXACT, cb_health);
}

void flb_hs_health_destroy()
{
    /* cleanup handled by flb_hs lifecycle */
    return;
}
