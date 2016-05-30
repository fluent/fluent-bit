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

#include <unistd.h>
#include <msgpack.h>

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>

#include "fw.h"
#include "fw_prot.h"
#include "fw_conn.h"

static int fw_process_array(struct flb_input_instance *in,
                            char *tag, int tag_len,
                            msgpack_object *arr)
{
    int i;
    msgpack_object p;

    for (i = 0; i < arr->via.array.size; i++) {
        p = arr->via.array.ptr[i];
        flb_input_dyntag_append(in, tag, tag_len, p);
    }

    return i;
}

int fw_prot_process(struct fw_conn *conn)
{
    int ret;
    int stag_len;
    char *stag;
    msgpack_object tag;
    msgpack_object entry;
    msgpack_object root;
    msgpack_unpacked result;

    /*
     * [tag, time, record]
     * [tag, [[time,record], [time,record], ...]]
     */

    msgpack_unpacked_init(&result);

    if (conn->buf_off == 0) {
        ret = msgpack_unpack_next(&result,
                                  conn->buf,
                                  conn->buf_len,
                                  &conn->buf_off);
        if (ret != MSGPACK_UNPACK_SUCCESS) {
            msgpack_unpacked_destroy(&result);
            switch (ret) {
            case MSGPACK_UNPACK_EXTRA_BYTES:
                flb_error("[in_fw] MSGPACK_UNPACK_EXTRA_BYTES");
                return -1;
            case MSGPACK_UNPACK_CONTINUE:
                flb_trace("[in_fw] MSGPACK_UNPACK_CONTINUE");
                return 1;
            case MSGPACK_UNPACK_PARSE_ERROR:
                flb_debug("[in_fw] err=MSGPACK_UNPACK_PARSE_ERROR");
                return -1;
            case MSGPACK_UNPACK_NOMEM_ERROR:
                flb_error("[in_fw] err=MSGPACK_UNPACK_NOMEM_ERROR");
                return -1;
            };
        }

        /* Map the array */
        root = result.data;
        if (root.via.array.size < 2) {
            flb_trace("[in_fw] parser: array of invalid size, skip.");
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        /* Get the tag */
        tag = root.via.array.ptr[0];
        if (tag.type != MSGPACK_OBJECT_STR) {
            flb_trace("[in_fw] parser: invalid tag format, skip.");
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        stag     = (char *) tag.via.str.ptr;
        stag_len = tag.via.str.size;

        entry = root.via.array.ptr[1];
        if (entry.type == MSGPACK_OBJECT_ARRAY) {
            fw_process_array(conn->in, stag, stag_len, &entry);
        }
        else if (entry.type == MSGPACK_OBJECT_MAP) {
            flb_input_dyntag_append(conn->in,
                                    stag, stag_len,
                                    entry);
        }
    }

    msgpack_unpacked_destroy(&result);

    return 0;
}
