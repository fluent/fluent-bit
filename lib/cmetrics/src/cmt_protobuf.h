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

#ifndef CMT_PROTOBUF_H
#define CMT_PROTOBUF_H

#include <fluent-otel-proto/fluent-otel.h>

/* Budget includes export/resource/scope wrappers and scalar AnyValue messages. */
#define CMT_PROTOBUF_MAX_DEPTH 100

struct cmt_protobuf_frame {
    const ProtobufCMessageDescriptor *descriptor;
    const unsigned char *cursor;
    const unsigned char *end;
};

static int cmt_protobuf_read_varint(struct cmt_protobuf_frame *frame, uint64_t *value)
{
    unsigned int shift;
    unsigned char byte;

    *value = 0;
    for (shift = 0; shift < 64; shift += 7) {
        if (frame->cursor == frame->end) {
            return -1;
        }
        byte = *frame->cursor++;
        if (shift == 63 && byte > 1) {
            return -1;
        }
        *value |= (uint64_t) (byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            return 0;
        }
    }
    return -1;
}

/*
 * Inspect known message fields before protobuf-c recursively allocates them.
 * Strings, bytes, packed scalars and unknown fields are opaque. The explicit
 * stack bounds our own stack usage as well as the subsequent unpack operation.
 */
static int cmt_protobuf_validate(const ProtobufCMessageDescriptor *descriptor,
                                    const void *data, size_t size)
{
    struct cmt_protobuf_frame frames[CMT_PROTOBUF_MAX_DEPTH];
    struct cmt_protobuf_frame *frame;
    const ProtobufCFieldDescriptor *field;
    const unsigned char *message;
    uint64_t tag;
    uint64_t length;
    size_t depth;

    if (descriptor == NULL || (data == NULL && size != 0)) {
        return -1;
    }
    if (size == 0) {
        return 0;
    }

    depth = 1;
    frames[0].descriptor = descriptor;
    frames[0].cursor = data;
    frames[0].end = frames[0].cursor + size;

    while (depth > 0) {
        frame = &frames[depth - 1];
        if (frame->cursor == frame->end) {
            depth--;
            continue;
        }
        if (cmt_protobuf_read_varint(frame, &tag) != 0 || tag >> 3 == 0 || tag >> 3 > 0x1fffffff) {
            return -1;
        }

        switch (tag & 7) {
        case 0:
            if (cmt_protobuf_read_varint(frame, &length) != 0) {
                return -1;
            }
            continue;
        case 1:
            length = 8;
            break;
        case 2:
            if (cmt_protobuf_read_varint(frame, &length) != 0) {
                return -1;
            }
            break;
        case 5:
            length = 4;
            break;
        default:
            /* Groups are unsupported by protobuf-c. */
            return -1;
        }

        if (length > (uint64_t) (frame->end - frame->cursor)) {
            return -1;
        }
        message = frame->cursor;
        frame->cursor += (size_t) length;
        if ((tag & 7) != 2) {
            continue;
        }
        field = protobuf_c_message_descriptor_get_field(frame->descriptor, tag >> 3);
        if (field == NULL || field->type != PROTOBUF_C_TYPE_MESSAGE) {
            continue;
        }
        if (depth >= CMT_PROTOBUF_MAX_DEPTH) {
            return -1;
        }
        frames[depth].descriptor = field->descriptor;
        frames[depth].cursor = message;
        frames[depth].end = message + (size_t) length;
        depth++;
    }
    return 0;
}

#endif
