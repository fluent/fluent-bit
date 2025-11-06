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

#ifndef FLB_NETWORK_VERIFIER_PLUGIN_H
#define FLB_NETWORK_VERIFIER_PLUGIN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_network_verifier.h>
#include <fluent-bit/flb_log.h>

#define flb_plg_log(ctx, level, fmt, ...)                                \
    if (flb_log_check_level(ctx->log_level, level))                      \
        flb_log_print(level, NULL, 0, "[network_verifier:%s:%s] " fmt,       \
                      ctx->plugin->name,                                 \
                      flb_network_verifier_get_alias(ctx), ##__VA_ARGS__)

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
