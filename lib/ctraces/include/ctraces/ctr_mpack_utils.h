/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 Eduardo Silva <eduardo@calyptia.com>
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

#ifndef CTR_MPACK_UTILS_H
#define CTR_MPACK_UTILS_H

#include <ctraces/ctr_mpack_utils_defs.h>
#include <cfl/cfl_sds.h>
#include <mpack/mpack.h>

typedef int (*ctr_mpack_unpacker_entry_callback_fn_t)(mpack_reader_t *reader,
                                                      size_t index, void *context);

struct ctr_mpack_map_entry_callback_t {
    const char                            *identifier;
    ctr_mpack_unpacker_entry_callback_fn_t handler;
};

int ctr_mpack_consume_nil_tag(mpack_reader_t *reader);
int ctr_mpack_consume_double_tag(mpack_reader_t *reader, double *output_buffer);
int ctr_mpack_consume_int_tag(mpack_reader_t *reader, int64_t *output_buffer);
int ctr_mpack_consume_int32_tag(mpack_reader_t *reader, int32_t *output_buffer);
int ctr_mpack_consume_int64_tag(mpack_reader_t *reader, int64_t *output_buffer);
int ctr_mpack_consume_uint_tag(mpack_reader_t *reader, uint64_t *output_buffer);
int ctr_mpack_consume_uint32_tag(mpack_reader_t *reader, uint32_t *output_buffer);
int ctr_mpack_consume_uint64_tag(mpack_reader_t *reader, uint64_t *output_buffer);
int ctr_mpack_consume_string_tag(mpack_reader_t *reader, cfl_sds_t *output_buffer);
int ctr_mpack_consume_binary_tag(mpack_reader_t *reader, cfl_sds_t *output_buffer);
int ctr_mpack_consume_string_or_nil_tag(mpack_reader_t *reader, cfl_sds_t *output_buffer);
int ctr_mpack_consume_binary_or_nil_tag(mpack_reader_t *reader, cfl_sds_t *output_buffer);
int ctr_mpack_unpack_map(mpack_reader_t *reader,
                         struct ctr_mpack_map_entry_callback_t *callback_list,
                         void *context);
int ctr_mpack_unpack_array(mpack_reader_t *reader,
                           ctr_mpack_unpacker_entry_callback_fn_t entry_processor_callback,
                           void *context);
int ctr_mpack_peek_array_length(mpack_reader_t *reader);
mpack_type_t ctr_mpack_peek_type(mpack_reader_t *reader);

#endif
