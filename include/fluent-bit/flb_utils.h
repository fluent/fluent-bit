/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#ifndef FLB_UTILS_H
#define FLB_UTILS_H

#include <fluent-bit/flb_config.h>

/* Message types */
#define FLB_MSG_INFO    0
#define FLB_MSG_WARN    1
#define FLB_MSG_ERROR   2
#define FLB_MSG_DEBUG   3
#define FLB_MSG_TRACE   4

#define flb_info(fmt, ...)    flb_message(FLB_MSG_INFO, NULL, 0, fmt, ##__VA_ARGS__)
#define flb_warn(fmt, ...)    flb_message(FLB_MSG_WARN, NULL, 0, fmt, ##__VA_ARGS__)
#define flb_error(fmt, ...)   flb_message(FLB_MSG_ERROR, NULL, 0, fmt, ##__VA_ARGS__)
#define flb_debug(c,fmt, ...) if (c->verbose) flb_message(FLB_MSG_DEBUG, \
                                                          NULL, 0,      \
                                                          fmt, ##__VA_ARGS__)

#ifdef FLB_TRACE
#define flb_trace(fmt, ...) \
    flb_message(FLB_MSG_TRACE, __FILE__, __LINE__, \
                fmt, ##__VA_ARGS__)
#else
#define flb_trace(fmt, ...)  do {} while(0)
#endif

int flb_debug_enabled();
void flb_utils_error(int err);
void flb_utils_error_c(const char *msg);
void flb_utils_warn_c(const char *msg);
void flb_message(int type, char *file, int line, const char *fmt, ...);
int flb_utils_set_daemon();
void flb_utils_print_setup(struct flb_config *config);

#endif
