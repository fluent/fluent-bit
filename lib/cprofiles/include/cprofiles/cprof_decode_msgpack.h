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

#ifndef CPROF_DECODE_MSGPACK_H
#define CPROF_DECODE_MSGPACK_H

#include <cprofiles/cprofiles.h>
#include <mpack/mpack.h>

#define CPROF_DECODE_MSGPACK_SUCCESS                0
#define CPROF_DECODE_MSGPACK_ALLOCATION_ERROR       1
#define CPROF_DECODE_MSGPACK_INSUFFICIENT_DATA      2
#define CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR 3

struct crof_msgpack_decode_context {
    struct cprof   *inner_context;
    mpack_reader_t  reader;
};

int cprof_decode_msgpack_create(struct cprof **result_context,
                                unsigned char *in_buf,
                                size_t in_size,
                                size_t *offset);

void cprof_decode_msgpack_destroy(struct cprof *context);

#endif
