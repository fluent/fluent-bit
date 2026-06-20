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

#ifndef FLB_SNAPPY_H
#define FLB_SNAPPY_H

#include <fluent-bit/flb_info.h>
#include <cfl/cfl_list.h>

#include <stdio.h>

#define FLB_SNAPPY_STREAM_IDENTIFIER_STRING     "sNaPpY"
#define FLB_SNAPPY_FRAME_SIZE_LIMIT             65540

#define FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER         0xFF
#define FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA           0x00
#define FLB_SNAPPY_FRAME_TYPE_UNCOMPRESSED_DATA         0x01
#define FLB_SNAPPY_FRAME_TYPE_RESERVED_UNSKIPPABLE_BASE 0x02
#define FLB_SNAPPY_FRAME_TYPE_RESERVED_UNSKIPPABLE_TOP  0x7F
#define FLB_SNAPPY_FRAME_TYPE_RESERVED_SKIPPABLE_BASE   0x80
#define FLB_SNAPPY_FRAME_TYPE_RESERVED_SKIPPABLE_TOP    0xFD
#define FLB_SNAPPY_FRAME_TYPE_PADDING                   0xFE

struct flb_snappy_data_chunk {
    int             dynamically_allocated_buffer;
    char           *buffer;
    size_t          length;

    struct cfl_list _head;
};

int flb_snappy_compress(char *in_data, size_t in_len,
                        char **out_data, size_t *out_len);

int flb_snappy_uncompress(char *in_data, size_t in_len,
                          char **out_data, size_t *out_size);

int flb_snappy_uncompress_framed_data(char *in_data, size_t in_len,
                                      char **out_data, size_t *out_len);

#endif
