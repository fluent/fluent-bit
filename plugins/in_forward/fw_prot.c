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
    msgpack_object entry;

    for (i = 0; i < arr->via.array.size; i++) {
        entry = arr->via.array.ptr[i];
        flb_input_dyntag_append(in, tag, tag_len, entry);
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
    msgpack_object map;
    msgpack_object root;
    msgpack_unpacked result;

    /*
     * [tag, time, record]
     * [tag, [[time,record], [time,record], ...]]
     */
    msgpack_unpacked_init(&result);
    while ((ret = msgpack_unpack_next(&result,
                                     conn->buf,
                                     conn->buf_len,
                                      &conn->buf_off))) {
        /* Map the array */
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            flb_debug("[in_fw] parser: expecting an array, skip.");
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        if (root.via.array.size < 2) {
            flb_debug("[in_fw] parser: array of invalid size, skip.");
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        /* Get the tag */
        tag = root.via.array.ptr[0];
        if (tag.type != MSGPACK_OBJECT_STR) {
            flb_debug("[in_fw] parser: invalid tag format, skip.");
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        stag     = (char *) tag.via.str.ptr;
        stag_len = tag.via.str.size;

        entry = root.via.array.ptr[1];
        if (entry.type == MSGPACK_OBJECT_ARRAY) {
            /* Forward format 1: [tag, [[time, map], ...]] */
            fw_process_array(conn->in, stag, stag_len, &entry);
        }
        else if (entry.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            /* Forward format 2: [tag, time, map] */
            map = root.via.array.ptr[2];
            if (map.type != MSGPACK_OBJECT_MAP) {
                flb_warn("[in_fw] invalid data format, map expected");
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            /* Compose the new array */
            struct msgpack_sbuffer mp_sbuf;
            struct msgpack_packer mp_pck;
            msgpack_unpacked r_out;
            size_t off = 0;

            msgpack_sbuffer_init(&mp_sbuf);
            msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

            msgpack_pack_array(&mp_pck, 2);
            msgpack_pack_object(&mp_pck, entry);
            msgpack_pack_object(&mp_pck, map);

            msgpack_unpacked_init(&r_out);
            msgpack_unpack_next(&r_out,
                                mp_sbuf.data,
                                mp_sbuf.size,
                                &off);

            entry = r_out.data;
            flb_input_dyntag_append(conn->in,
                                    stag, stag_len,
                                    entry);

            msgpack_unpacked_destroy(&r_out);
            msgpack_sbuffer_destroy(&mp_sbuf);
        }
        else {
            flb_warn("[in_fw] invalid data format");
            msgpack_unpacked_destroy(&result);
            return -1;
        }
    }
    msgpack_unpacked_destroy(&result);

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

    if (conn->buf_off > 0) {
        memmove(conn->buf, conn->buf + conn->buf_off, conn->buf_off);
        conn->buf_len -= conn->buf_off;
        if (conn->buf_len == 0) {
            conn->buf_off = 0;
        }
    }

    return 0;
}
