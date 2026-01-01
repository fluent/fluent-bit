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

#ifndef FLB_PROCESSOR_PLUGIN_H
#define FLB_PROCESSOR_PLUGIN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_mp_chunk.h>

#define flb_plg_log(ctx, level, fmt, ...)                                \
    if (flb_log_check_level(ctx->log_level, level))                      \
        flb_log_print(level, NULL, 0, "[processor:%s:%s] " fmt,          \
                      ctx->p->name,                                      \
                      flb_processor_instance_get_name(ctx), ##__VA_ARGS__)

#define flb_plg_error(ctx, fmt, ...) \
    flb_plg_log(ctx, FLB_LOG_ERROR, fmt, ##__VA_ARGS__)

#define flb_plg_warn(ctx, fmt, ...)  \
    flb_plg_log(ctx, FLB_LOG_WARN, fmt, ##__VA_ARGS__)

#define flb_plg_info(ctx, fmt, ...)  \
    flb_plg_log(ctx, FLB_LOG_INFO, fmt, ##__VA_ARGS__)

#define flb_plg_debug(ctx, fmt, ...) \
    flb_plg_log(ctx, FLB_LOG_DEBUG, fmt, ##__VA_ARGS__)

#define flb_plg_trace(ctx, fmt, ...) \
    flb_plg_log(ctx, FLB_LOG_TRACE, fmt, ##__VA_ARGS__)
#endif
