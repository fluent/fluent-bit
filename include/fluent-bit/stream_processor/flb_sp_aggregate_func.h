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

#ifndef FLB_SP_AGGREGATE_FUNC_H
#define FLB_SP_AGGREGATE_FUNC_H


typedef void (*aggregate_function_destroy)(struct aggregate_node *,
                                           int);

typedef int (*aggregate_function_clone)(struct aggregate_node *,
                                        struct aggregate_node *,
                                        struct flb_sp_cmd_key *,
                                        int);

typedef void (*aggregate_function_add)(struct aggregate_node *,
                                       struct flb_sp_cmd_key *,
                                       int,
                                       struct flb_time *,
                                       int64_t, double);

typedef void (*aggregate_function_calc)(struct aggregate_node *,
                                        struct flb_sp_cmd_key *,
                                        msgpack_packer *,
                                        int);

typedef void (*aggregate_function_remove)(struct aggregate_node *,
                                          struct aggregate_node *,
                                          int);

extern char aggregate_func_string[AGGREGATE_FUNCTIONS][sizeof("TIMESERIES_FORECAST") + 1];

extern aggregate_function_clone aggregate_func_clone[AGGREGATE_FUNCTIONS];
extern aggregate_function_add aggregate_func_add[AGGREGATE_FUNCTIONS];
extern aggregate_function_calc aggregate_func_calc[AGGREGATE_FUNCTIONS];
extern aggregate_function_remove aggregate_func_remove[AGGREGATE_FUNCTIONS];
extern aggregate_function_destroy aggregate_func_destroy[AGGREGATE_FUNCTIONS];

#endif
