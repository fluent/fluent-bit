/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <msgpack.h>

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>

#include "fw.h"
#include "fw_prot.h"
#include "fw_conn.h"

/* Try parsing rounds up-to 32 bytes */
#define EACH_RECV_SIZE 32

static int fw_process_array(struct flb_input_instance *in,
                            char *tag, int tag_len,
                            msgpack_object *arr)
{
    int i;
    msgpack_object entry;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /*
     * This process is not quite optimal from a performance perspective,
     * we need to fix it later, likely using the offset of the original
     * msgpack buffer.
     *
     * For now we iterate the array and append each entry into a chunk
     */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    for (i = 0; i < arr->via.array.size; i++) {
        entry = arr->via.array.ptr[i];
        msgpack_pack_object(&mp_pck, entry);
    }

    flb_input_chunk_append_raw(in, tag, tag_len, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return i;
}

static size_t receiver_recv(struct fw_conn *conn, char *buf, size_t try_size) {
    size_t off;
    size_t actual_size;

    off = conn->buf_len - conn->rest;
    actual_size = try_size;

    if (actual_size > conn->rest) {
        actual_size = conn->rest;
    }

    memcpy(buf, conn->buf + off, actual_size);
    conn->rest -= actual_size;

    return actual_size;
}

static size_t receiver_to_unpacker(struct fw_conn *conn, size_t request_size,
                                   msgpack_unpacker *unpacker)
{
    size_t recv_len;

    /* make sure there's enough room, or expand the unpacker accordingly */
    if (msgpack_unpacker_buffer_capacity(unpacker) < request_size) {
        msgpack_unpacker_reserve_buffer(unpacker, request_size);
        assert(msgpack_unpacker_buffer_capacity(unpacker) >= request_size);
    }
    recv_len = receiver_recv(conn, msgpack_unpacker_buffer(unpacker),
                             request_size);
    msgpack_unpacker_buffer_consumed(unpacker, recv_len);

    return recv_len;
}

int fw_prot_process(struct fw_conn *conn)
{
    int ret;
    int stag_len;
    int c = 0;
    char *stag;
    size_t bytes;
    size_t buf_off = 0;
    size_t recv_len;
    msgpack_object tag;
    msgpack_object entry;
    msgpack_object map;
    msgpack_object root;
    msgpack_unpacked result;
    msgpack_unpacker *unp;
    size_t all_used = 0;

    /*
     * [tag, time, record]
     * [tag, [[time,record], [time,record], ...]]
     */

    unp = msgpack_unpacker_new(1024);
    msgpack_unpacked_init(&result);
    conn->rest = conn->buf_len;

    while (1) {
        recv_len = receiver_to_unpacker(conn, EACH_RECV_SIZE, unp);
        if (recv_len == 0) {
            /* No more data */
            msgpack_unpacker_free(unp);
            msgpack_unpacked_destroy(&result);

            /* Adjust buffer data */
            if (all_used > 0) {
                memmove(conn->buf, conn->buf + all_used,
                        conn->buf_len - all_used);
                conn->buf_len -= all_used;
            }

            return 0;
        }

        /* Always summarize the total number of bytes requested to parse */
        buf_off += recv_len;

        ret = msgpack_unpacker_next_with_size(unp, &result, &bytes);
        while (ret == MSGPACK_UNPACK_SUCCESS) {
            /*
             * For buffering optimization we always want to know the total
             * number of bytes involved on the new object returned. Despites
             * buf_off always know the given bytes, it's likely we used a bit
             * less. This 'all_used' field keep a reference per object so
             * when returning to the caller we can adjust the source buffer
             * and deprecated consumed data.
             *
             * The 'last_parsed' field is Fluent Bit specific and is documented
             * in:
             *
             *  lib/msgpack-c/include/msgpack/unpack.h
             *
             * Other references:
             *
             *  https://github.com/msgpack/msgpack-c/issues/514
             */
            all_used += bytes;


            /* Map the array */
            root = result.data;

            if (root.type != MSGPACK_OBJECT_ARRAY) {
                flb_debug("[in_fw] parser: expecting an array (type=%i), skip.",
                          root.type);
                msgpack_unpacked_destroy(&result);
                msgpack_unpacker_free(unp);
                return -1;
            }

            if (root.via.array.size < 2) {
                flb_debug("[in_fw] parser: array of invalid size, skip.");
                msgpack_unpacked_destroy(&result);
                msgpack_unpacker_free(unp);
                return -1;
            }

            /* Get the tag */
            tag = root.via.array.ptr[0];
            if (tag.type != MSGPACK_OBJECT_STR) {
                flb_debug("[in_fw] parser: invalid tag format, skip.");
                msgpack_unpacked_destroy(&result);
                msgpack_unpacker_free(unp);
                return -1;
            }

            stag     = (char *) tag.via.str.ptr;
            stag_len = tag.via.str.size;

            entry = root.via.array.ptr[1];
            if (entry.type == MSGPACK_OBJECT_ARRAY) {
                /* Forward format 1: [tag, [[time, map], ...]] */
                fw_process_array(conn->in, stag, stag_len, &entry);
            }
            else if (entry.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
                     entry.type == MSGPACK_OBJECT_EXT) {
                /* Forward format 2: [tag, time, map] */
                map = root.via.array.ptr[2];
                if (map.type != MSGPACK_OBJECT_MAP) {
                    flb_warn("[in_fw] invalid data format, map expected");
                    msgpack_unpacked_destroy(&result);
                    msgpack_unpacker_free(unp);
                    return -1;
                }

                /* Compose the new array */
                struct msgpack_sbuffer mp_sbuf;
                struct msgpack_packer mp_pck;

                msgpack_sbuffer_init(&mp_sbuf);
                msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

                msgpack_pack_array(&mp_pck, 2);
                msgpack_pack_object(&mp_pck, entry);
                msgpack_pack_object(&mp_pck, map);

                /* Register data object */
                flb_input_chunk_append_raw(conn->in, stag, stag_len,
                                           mp_sbuf.data, mp_sbuf.size);
                msgpack_sbuffer_destroy(&mp_sbuf);
                c++;
            }
            else if (entry.type == MSGPACK_OBJECT_STR ||
                     entry.type == MSGPACK_OBJECT_BIN) {
                /* PackedForward Mode */
                char *data = NULL;
                size_t len = 0;

                if (entry.type == MSGPACK_OBJECT_STR) {
                    data = (char *) entry.via.str.ptr;
                    len = entry.via.str.size;
                }
                else if (entry.type == MSGPACK_OBJECT_BIN) {
                    data = (char *) entry.via.bin.ptr;
                    len = entry.via.bin.size;
                }

                if (data) {
                    flb_input_chunk_append_raw(conn->in,
                                               stag, stag_len,
                                               data, len);
                }
            }
            else {
                flb_warn("[in_fw] invalid data format, type=%i",
                         entry.type);
                msgpack_unpacked_destroy(&result);
                msgpack_unpacker_free(unp);
                return -1;
            }

            ret = msgpack_unpacker_next(unp, &result);
        }
    }
    msgpack_unpacked_destroy(&result);
    msgpack_unpacker_free(unp);

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

    return 0;
}
