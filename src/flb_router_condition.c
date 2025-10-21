/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_router.h>

uint32_t flb_router_signal_from_chunk(struct flb_event_chunk *chunk)
{
    if (!chunk) {
        return 0;
    }

    switch (chunk->type) {
    case FLB_EVENT_TYPE_LOGS:
        return FLB_ROUTER_SIGNAL_LOGS;
    case FLB_EVENT_TYPE_METRICS:
        return FLB_ROUTER_SIGNAL_METRICS;
    case FLB_EVENT_TYPE_TRACES:
        return FLB_ROUTER_SIGNAL_TRACES;
    default:
        break;
    }

    return 0;
}

int flb_condition_eval_logs(struct flb_event_chunk *chunk,
                            struct flb_route *route)
{
    (void) chunk;
    (void) route;

    /*
     * The full condition evaluation engine requires field resolvers that map
     * record accessors to the different telemetry payload shapes.  The wiring
     * of those resolvers is part of a bigger effort and will be implemented in
     * follow-up changes.  For the time being we simply report that the
     * condition failed so that the runtime can rely on explicit default
     * routes.
     */
    return FLB_FALSE;
}

int flb_condition_eval_metrics(struct flb_event_chunk *chunk,
                               struct flb_route *route)
{
    (void) chunk;
    (void) route;

    return FLB_FALSE;
}

int flb_condition_eval_traces(struct flb_event_chunk *chunk,
                              struct flb_route *route)
{
    (void) chunk;
    (void) route;

    return FLB_FALSE;
}

int flb_route_condition_eval(struct flb_event_chunk *chunk,
                             struct flb_route *route)
{
    uint32_t signal;

    if (!route) {
        return FLB_FALSE;
    }

    if (!route->condition) {
        return FLB_TRUE;
    }

    signal = flb_router_signal_from_chunk(chunk);
    if (signal == 0) {
        return FLB_FALSE;
    }

    if ((route->signals != 0) && (route->signals != FLB_ROUTER_SIGNAL_ANY) &&
        ((route->signals & signal) == 0)) {
        return FLB_FALSE;
    }

    if (route->condition->is_default) {
        return FLB_TRUE;
    }

    if (cfl_list_is_empty(&route->condition->rules) == 0) {
        return FLB_TRUE;
    }

    switch (signal) {
    case FLB_ROUTER_SIGNAL_LOGS:
        return flb_condition_eval_logs(chunk, route);
    case FLB_ROUTER_SIGNAL_METRICS:
        return flb_condition_eval_metrics(chunk, route);
    case FLB_ROUTER_SIGNAL_TRACES:
        return flb_condition_eval_traces(chunk, route);
    default:
        break;
    }

    return FLB_FALSE;
}

