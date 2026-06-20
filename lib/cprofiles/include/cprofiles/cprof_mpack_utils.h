/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CProfiles
 *  ========
 *  Copyright 2024 The CProfiles Authors
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

#ifndef CPROF_MPACK_UTILS_H
#define CPROF_MPACK_UTILS_H

#include <cprofiles/cprofiles.h>
#include <cprofiles/cprof_mpack_utils_defs.h>
#include <mpack/mpack.h>

typedef int (*cprof_mpack_unpacker_entry_callback_fn_t)(mpack_reader_t *reader,
                                                        size_t index,
                                                        void *context);

struct cprof_mpack_map_entry_callback_t {
    const char                              *identifier;
    cprof_mpack_unpacker_entry_callback_fn_t  handler;
};

int cprof_mpack_consume_nil_tag(mpack_reader_t *reader);
int cprof_mpack_consume_double_tag(mpack_reader_t *reader, double *output_buffer);
int cprof_mpack_consume_int_tag(mpack_reader_t *reader, int64_t *output_buffer);
int cprof_mpack_consume_int32_tag(mpack_reader_t *reader, int32_t *output_buffer);
int cprof_mpack_consume_int64_tag(mpack_reader_t *reader, int64_t *output_buffer);
int cprof_mpack_consume_uint_tag(mpack_reader_t *reader, uint64_t *output_buffer);
int cprof_mpack_consume_uint32_tag(mpack_reader_t *reader, uint32_t *output_buffer);
int cprof_mpack_consume_uint64_tag(mpack_reader_t *reader, uint64_t *output_buffer);
int cprof_mpack_consume_string_tag(mpack_reader_t *reader, cfl_sds_t *output_buffer);
int cprof_mpack_consume_binary_tag(mpack_reader_t *reader, cfl_sds_t *output_buffer);
int cprof_mpack_consume_string_or_nil_tag(mpack_reader_t *reader, cfl_sds_t *output_buffer);
int cprof_mpack_consume_binary_or_nil_tag(mpack_reader_t *reader, cfl_sds_t *output_buffer);
int cprof_mpack_unpack_map(mpack_reader_t *reader,
                         struct cprof_mpack_map_entry_callback_t *callback_list,
                         void *context);
int cprof_mpack_unpack_array(mpack_reader_t *reader,
                           cprof_mpack_unpacker_entry_callback_fn_t entry_processor_callback,
                           void *context);
int cprof_mpack_peek_array_length(mpack_reader_t *reader);
mpack_type_t cprof_mpack_peek_type(mpack_reader_t *reader);

#endif
