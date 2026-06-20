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

#ifndef FLB_SP_STREAM_H
#define FLB_SP_STREAM_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>

struct flb_sp_stream {
    flb_sds_t name;       /* stream name */
    flb_sds_t tag;        /* tag specified through properties */
    int routable;         /* is it routable ? */
    void *in;             /* input instance context */
};

int flb_sp_stream_create(const char *name, struct flb_sp_task *task,
                         struct flb_sp *sp);
void flb_sp_stream_destroy(struct flb_sp_stream *stream, struct flb_sp *sp);

int flb_sp_stream_append_data(const char *buf_data, size_t buf_size,
                              struct flb_sp_stream *stream);

#endif
