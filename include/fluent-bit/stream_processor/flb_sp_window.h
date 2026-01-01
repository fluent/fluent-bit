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

#ifndef FLB_SP_WINDOW
#define FLB_SP_WINDOW

#include <fluent-bit/stream_processor/flb_sp.h>

#define FLB_SP_WINDOW_DEFAULT   0
#define FLB_SP_WINDOW_TUMBLING  1
#define FLB_SP_WINDOW_HOPPING   2

void flb_sp_window_prune(struct flb_sp_task *task);
int flb_sp_window_populate(struct flb_sp_task *task, const char *buf_data,
                           size_t buf_size);

#endif
