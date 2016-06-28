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

#include <fluent-bit/flb_info.h>

#ifdef FLB_HAVE_BUFFERING

#include <mk_core.h>
#include <fluent-bit/flb_buffer.h>

#ifndef FLB_BUFFER_CHUNK_H
#define FLB_BUFFER_CHUNK_H

#define FLB_BUFFER_CHUNK_INCOMING 0
#define FLB_BUFFER_CHUNK_OUTGOING 1
#define FLB_BUFFER_CHUNK_DEFERRED 3

int flb_buffer_chunk_add(struct flb_buffer_worker *worker,
                         struct mk_event *event, char **filename);
struct flb_buffer_request *flb_buffer_chunk_mov(int type,
                                                char *name,
                                                struct flb_buffer_worker *worker);

int flb_buffer_chunk_real_move(struct flb_buffer_worker *worker,
                               struct mk_event *event);

#endif

#endif /* !FLB_HAVE_BUFFERING */
