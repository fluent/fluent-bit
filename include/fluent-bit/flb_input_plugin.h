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

#ifndef FLB_INPUT_PLUGIN_H
#define FLB_INPUT_PLUGIN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_metric.h>
#include <fluent-bit/flb_log.h>

#define flb_input_plugin_log_suppress_check(ins, fmt, ...) \
    flb_log_suppress_check(ins->log_suppress_interval, fmt, ##__VA_ARGS__)


#define flb_plg_error(ctx, fmt, ...)                                    \
    if (flb_log_check_level(ctx->log_level, FLB_LOG_ERROR))             \
        if (flb_input_plugin_log_suppress_check(ctx, fmt, ##__VA_ARGS__) == FLB_FALSE) \
            flb_log_print(FLB_LOG_ERROR, NULL, 0, "[input:%s:%s] " fmt, \
                          ctx->p->name, flb_input_name(ctx), ##__VA_ARGS__)

#define flb_plg_warn(ctx, fmt, ...)                                     \
    if (flb_log_check_level(ctx->log_level, FLB_LOG_WARN))              \
        if (flb_input_plugin_log_suppress_check(ctx, fmt, ##__VA_ARGS__) == FLB_FALSE) \
            flb_log_print(FLB_LOG_WARN, NULL, 0, "[input:%s:%s] " fmt,  \
                          ctx->p->name, flb_input_name(ctx), ##__VA_ARGS__)

#define flb_plg_info(ctx, fmt, ...)                                     \
    if (flb_log_check_level(ctx->log_level, FLB_LOG_INFO))                             \
        if (flb_input_plugin_log_suppress_check(ctx, fmt, ##__VA_ARGS__) == FLB_FALSE) \
            flb_log_print(FLB_LOG_INFO, NULL, 0, "[input:%s:%s] " fmt,  \
                          ctx->p->name, flb_input_name(ctx), ##__VA_ARGS__)

#define flb_plg_debug(ctx, fmt, ...)                                    \
    if (flb_log_check_level(ctx->log_level, FLB_LOG_DEBUG))             \
        if (flb_input_plugin_log_suppress_check(ctx, fmt, ##__VA_ARGS__) == FLB_FALSE) \
            flb_log_print(FLB_LOG_DEBUG, NULL, 0, "[input:%s:%s] " fmt, \
                          ctx->p->name, flb_input_name(ctx), ##__VA_ARGS__)

#define flb_plg_trace(ctx, fmt, ...)                                    \
    if (flb_log_check_level(ctx->log_level, FLB_LOG_TRACE))             \
        if (flb_input_plugin_log_suppress_check(ctx, fmt, ##__VA_ARGS__) == FLB_FALSE) \
            flb_log_print(FLB_LOG_TRACE, NULL, 0,                       \
                          "[input:%s:%s at %s:%i] " fmt,                \
                          ctx->p->name, flb_input_name(ctx), __FLB_FILENAME__, \
                          __LINE__, ##__VA_ARGS__)
#endif
