/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#ifndef CMT_MPACK_UTILS_H
#define CMT_MPACK_UTILS_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_mpack_utils_defs.h>
#include <mpack/mpack.h>

typedef int (*cmt_mpack_unpacker_entry_callback_fn_t)(mpack_reader_t *reader, 
                                                      size_t index, void *context);

struct cmt_mpack_map_entry_callback_t {
    const char                            *identifier;
    cmt_mpack_unpacker_entry_callback_fn_t handler;
};

int cmt_mpack_consume_double_tag(mpack_reader_t *reader, double *output_buffer);
int cmt_mpack_consume_int_tag(mpack_reader_t *reader, int64_t *output_buffer);
int cmt_mpack_consume_uint_tag(mpack_reader_t *reader, uint64_t *output_buffer);
int cmt_mpack_consume_string_tag(mpack_reader_t *reader, cfl_sds_t *output_buffer);
int cmt_mpack_unpack_map(mpack_reader_t *reader, 
                         struct cmt_mpack_map_entry_callback_t *callback_list, 
                         void *context);
int cmt_mpack_unpack_array(mpack_reader_t *reader, 
                           cmt_mpack_unpacker_entry_callback_fn_t entry_processor_callback, 
                           void *context);
int cmt_mpack_peek_array_length(mpack_reader_t *reader);

#endif
