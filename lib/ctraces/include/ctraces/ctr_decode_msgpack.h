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

#ifndef CTR_DECODE_MSGPACK_H
#define CTR_DECODE_MSGPACK_H

#include <ctraces/ctraces.h>

#define CTR_DECODE_MSGPACK_SUCCESS                (CTR_MPACK_SUCCESS)
#define CTR_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR (CTR_MPACK_INVALID_ARGUMENT_ERROR)
#define CTR_DECODE_MSGPACK_INVALID_STATE          (CTR_MPACK_ERROR_CUTOFF + 1)
#define CTR_DECODE_MSGPACK_ALLOCATION_ERROR       (CTR_MPACK_ERROR_CUTOFF + 2)
#define CTR_DECODE_MSGPACK_VARIANT_DECODE_ERROR   (CTR_MPACK_ERROR_CUTOFF + 3)

struct ctr_msgpack_decode_context {
    struct ctrace_resource_span *resource_span;
    struct ctrace_scope_span    *scope_span;
    struct ctrace_resource      *resource;
    struct ctrace               *trace;
    struct ctrace_span_event    *event;
    struct ctrace_span          *span;
    struct ctrace_link          *link;
};

int ctr_decode_msgpack_create(struct ctrace **out_context, char *in_buf, size_t in_size, size_t *offset);
void ctr_decode_msgpack_destroy(struct ctrace *context);

#endif
