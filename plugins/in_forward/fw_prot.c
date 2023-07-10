/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_gzip.h>

#include <fluent-bit/flb_input_metric.h>
#include <fluent-bit/flb_input_trace.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_decode_msgpack.h>

#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>

#include <msgpack.h>

#include "fw.h"
#include "fw_prot.h"
#include "fw_conn.h"

/* Try parsing rounds up-to 32 bytes */
#define EACH_RECV_SIZE 32

static int get_chunk_event_type(struct flb_input_instance *ins, msgpack_object options)
{
    int i;
    int type = FLB_EVENT_TYPE_LOGS;
    msgpack_object k;
    msgpack_object v;

    if (options.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ins, "invalid options field in record");
        return -1;
    }

    for (i = 0; i < options.via.map.size; i++) {
        k = options.via.map.ptr[i].key;
        v = options.via.map.ptr[i].val;

        if (k.type != MSGPACK_OBJECT_STR) {
            return -1;
        }

        if (k.via.str.size != 13) {
            continue;
        }

        if (strncmp(k.via.str.ptr, "fluent_signal", 13) == 0) {
            if (v.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
                flb_plg_error(ins, "invalid value type in options fluent_signal");
                return -1;
            }

            if (v.via.i64 != FLB_EVENT_TYPE_LOGS && v.via.i64 != FLB_EVENT_TYPE_METRICS && v.via.i64 != FLB_EVENT_TYPE_TRACES) {
                flb_plg_error(ins, "invalid value in options fluent_signal");
                return -1;
            }

            /* cast should be fine */
            type = (int) v.via.i64;
            break;
        }
    }

    return type;
}

static int is_gzip_compressed(msgpack_object options)
{
    int i;
    msgpack_object k;
    msgpack_object v;

    if (options.type != MSGPACK_OBJECT_MAP) {
        return -1;
    }


    for (i = 0; i < options.via.map.size; i++) {
        k = options.via.map.ptr[i].key;
        v = options.via.map.ptr[i].val;

        if (k.type != MSGPACK_OBJECT_STR) {
            return -1;
        }

        if (k.via.str.size != 10) {
            continue;
        }

        if (strncmp(k.via.str.ptr, "compressed", 10) == 0) {
            if (v.type != MSGPACK_OBJECT_STR) {
                return -1;
            }

            if (v.via.str.size != 4) {
                return -1;
            }

            if (strncmp(v.via.str.ptr, "gzip", 4) == 0) {
                return FLB_TRUE;
            }
            else if (strncmp(v.via.str.ptr, "text", 4) == 0) {
                return FLB_FALSE;
            }

            return -1;
        }
    }

    return FLB_FALSE;
}

static int send_ack(struct flb_input_instance *in, struct fw_conn *conn,
                    msgpack_object chunk)
{
    int result;
    size_t sent;
    ssize_t bytes;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 3);
    msgpack_pack_str_body(&mp_pck, "ack", 3);
    msgpack_pack_object(&mp_pck, chunk);


    bytes = flb_io_net_write(conn->connection,
                             (void *) mp_sbuf.data,
                             mp_sbuf.size,
                             &sent);

    msgpack_sbuffer_destroy(&mp_sbuf);

    if (bytes == -1) {
        flb_plg_error(in, "cannot send ACK response: %.*s",
                      chunk.via.str.size, chunk.via.str.ptr);

        result = -1;
    }
    else {
        result = 0;
    }

    return result;

}

static size_t get_options_metadata(msgpack_object *arr, int expected, size_t *idx)
{
    size_t i;
    msgpack_object *options;
    msgpack_object k;
    msgpack_object v;

    if (arr->type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    /* Make sure the 'expected' entry position is valid for the array size */
    if (expected >= arr->via.array.size) {
        return 0;
    }

    options = &arr->via.array.ptr[expected];
    if (options->type == MSGPACK_OBJECT_NIL) {
        /*
         * Old Docker 18.x sends a NULL options parameter, just be friendly and
         * let it pass.
         */
        return 0;
    }

    if (options->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    if (options->via.map.size <= 0) {
        return 0;
    }

    for (i = 0; i < options->via.map.size; i++) {
        k = options->via.map.ptr[i].key;
        v = options->via.map.ptr[i].val;

        if (k.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (k.via.str.size != 8) {
            continue;
        }

        if (strncmp(k.via.str.ptr, "metadata", 8) != 0) {
            continue;
        }

        if (v.type != MSGPACK_OBJECT_MAP) {
            return -1;
        }

        *idx = i;

        return 0;
    }

    return 0;
}

static size_t get_options_chunk(msgpack_object *arr, int expected, size_t *idx)
{
    size_t i;
    msgpack_object *options;
    msgpack_object k;
    msgpack_object v;

    if (arr->type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    /* Make sure the 'expected' entry position is valid for the array size */
    if (expected >= arr->via.array.size) {
        return 0;
    }

    options = &arr->via.array.ptr[expected];
    if (options->type == MSGPACK_OBJECT_NIL) {
        /*
         * Old Docker 18.x sends a NULL options parameter, just be friendly and
         * let it pass.
         */
        return 0;
    }

    if (options->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    if (options->via.map.size <= 0) {
        return 0;
    }

    for (i = 0; i < options->via.map.size; i++) {
        k = options->via.map.ptr[i].key;
        v = options->via.map.ptr[i].val;

        if (k.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (k.via.str.size != 5) {
            continue;
        }

        if (strncmp(k.via.str.ptr, "chunk", 5) != 0) {
            continue;
        }

        if (v.type != MSGPACK_OBJECT_STR) {
            return -1;
        }

        *idx = i;
        return 0;
    }

    return 0;
}

static int fw_process_forward_mode_entry(
                struct fw_conn *conn,
                const char *tag, int tag_len,
                msgpack_object *entry,
                int chunk_id)
{
    int                  result;
    struct flb_log_event event;

    result = flb_event_decoder_decode_object(conn->ctx->log_decoder,
                                             &event, entry);

    if (result == FLB_EVENT_DECODER_SUCCESS) {
        result = flb_log_event_encoder_begin_record(conn->ctx->log_encoder);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_timestamp(conn->ctx->log_encoder,
                                                     &event.timestamp);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_metadata_from_msgpack_object(
                    conn->ctx->log_encoder,
                    event.metadata);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_body_from_msgpack_object(
                    conn->ctx->log_encoder,
                    event.body);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(conn->ctx->log_encoder);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(conn->ctx->ins, tag, tag_len,
                             conn->ctx->log_encoder->output_buffer,
                             conn->ctx->log_encoder->output_length);
    }

    flb_log_event_encoder_reset(conn->ctx->log_encoder);

    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_warn(conn->ctx->ins, "Event decoder failure : %d", result);

        return -1;
    }

    return 0;
}

static int fw_process_message_mode_entry(
                struct flb_input_instance *in,
                struct fw_conn *conn,
                const char *tag, int tag_len,
                msgpack_object *root,
                msgpack_object *ts,
                msgpack_object *body,
                int chunk_id, int metadata_id)
{
    struct flb_time  timestamp;
    msgpack_object  *metadata;
    msgpack_object   options;
    int              result;
    msgpack_object   chunk;

    metadata = NULL;

    if (chunk_id != -1 || metadata_id != -1) {
        options = root->via.array.ptr[3];

        if (metadata_id != -1) {
            metadata = &options.via.map.ptr[metadata_id].val;
        }
    }

    result = flb_log_event_decoder_decode_timestamp(ts, &timestamp);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_begin_record(conn->ctx->log_encoder);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_timestamp(conn->ctx->log_encoder,
                                                     &timestamp);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        if (metadata != NULL) {
            result = flb_log_event_encoder_set_metadata_from_msgpack_object(
                        conn->ctx->log_encoder,
                        metadata);
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_body_from_msgpack_object(
                    conn->ctx->log_encoder,
                    body);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(conn->ctx->log_encoder);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(in, tag, tag_len,
                             conn->ctx->log_encoder->output_buffer,
                             conn->ctx->log_encoder->output_length);
    }

    flb_log_event_encoder_reset(conn->ctx->log_encoder);

    if (chunk_id != -1) {
        chunk = options.via.map.ptr[chunk_id].val;
        send_ack(in, conn, chunk);
    }

    return 0;
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

int fw_prot_process(struct flb_input_instance *ins, struct fw_conn *conn)
{
    int ret;
    int stag_len;
    int c = 0;
    int event_type;
    int contain_options = FLB_FALSE;
    size_t index = 0;
    size_t off = 0;
    size_t chunk_id = -1;
    size_t metadata_id = -1;
    const char *stag;
    flb_sds_t out_tag = NULL;
    size_t bytes;
    size_t recv_len;
    size_t gz_size;
    void *gz_data;
    msgpack_object tag;
    msgpack_object entry;
    msgpack_object map;
    msgpack_object root;
    msgpack_object chunk;
    msgpack_unpacked result;
    msgpack_unpacker *unp;
    size_t all_used = 0;
    struct flb_in_fw_config *ctx = conn->ctx;
    struct cmt *cmt;
    struct ctrace *ctr;

    /*
     * [tag, time, record]
     * [tag, [[time,record], [time,record], ...]]
     */

    out_tag = flb_sds_create_size(1024);
    if (!out_tag) {
        return -1;
    }

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
            if (conn->buf_len >= all_used && all_used > 0) {
                memmove(conn->buf, conn->buf + all_used,
                        conn->buf_len - all_used);
                conn->buf_len -= all_used;
            }
            flb_sds_destroy(out_tag);

            return 0;
        }

        /* Always summarize the total number of bytes requested to parse */
        ret = msgpack_unpacker_next_with_size(unp, &result, &bytes);

        /*
         * Upon parsing or memory errors, break the loop, return the error
         * and expect the connection to be closed.
         */
        if (ret == MSGPACK_UNPACK_PARSE_ERROR ||
            ret == MSGPACK_UNPACK_NOMEM_ERROR) {
            /* A bit redunant, print out the real error */
            if (ret == MSGPACK_UNPACK_PARSE_ERROR) {
                flb_plg_debug(ctx->ins, "err=MSGPACK_UNPACK_PARSE_ERROR");
            }
            else {
                flb_plg_error(ctx->ins, "err=MSGPACK_UNPACK_NOMEM_ERROR");
            }

            /* Cleanup buffers */
            msgpack_unpacked_destroy(&result);
            msgpack_unpacker_free(unp);
            flb_sds_destroy(out_tag);

            return -1;
        }

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
                flb_plg_debug(ctx->ins,
                              "parser: expecting an array (type=%i), skip.",
                              root.type);
                msgpack_unpacked_destroy(&result);
                msgpack_unpacker_free(unp);
                flb_sds_destroy(out_tag);

                return -1;
            }

            if (root.via.array.size < 2) {
                flb_plg_debug(ctx->ins,
                              "parser: array of invalid size, skip.");
                msgpack_unpacked_destroy(&result);
                msgpack_unpacker_free(unp);
                flb_sds_destroy(out_tag);

                return -1;
            }

            if (root.via.array.size == 3) {
                contain_options = FLB_TRUE;
            }

            /* Get the tag */
            tag = root.via.array.ptr[0];
            if (tag.type != MSGPACK_OBJECT_STR) {
                flb_plg_debug(ctx->ins,
                              "parser: invalid tag format, skip.");
                msgpack_unpacked_destroy(&result);
                msgpack_unpacker_free(unp);
                flb_sds_destroy(out_tag);
                return -1;
            }

            /* reference the tag associated with the record */
            stag     = tag.via.str.ptr;
            stag_len = tag.via.str.size;

            /* clear out_tag before using */
            flb_sds_len_set(out_tag, 0);

            /* Prefix the incoming record tag with a custom prefix */
            if (ctx->tag_prefix) {
                /* prefix */
                flb_sds_cat_safe(&out_tag,
                                 ctx->tag_prefix, flb_sds_len(ctx->tag_prefix));
                /* record tag */
                flb_sds_cat_safe(&out_tag, stag, stag_len);
            }
            else if (ins->tag && !ins->tag_default) {
                /* if the input plugin instance Tag has been manually set, use it */
                flb_sds_cat_safe(&out_tag, ins->tag, flb_sds_len(ins->tag));
            }
            else {
                /* use the tag from the record */
                flb_sds_cat_safe(&out_tag, stag, stag_len);
            }

            entry = root.via.array.ptr[1];

            if (entry.type == MSGPACK_OBJECT_ARRAY) {
                /*
                 * Forward format 1 (forward mode: [tag, [[time, map], ...]]
                 */

                /* Check for options */
                chunk_id = -1;
                ret = get_options_chunk(&root, 2, &chunk_id);
                if (ret == -1) {
                    flb_plg_debug(ctx->ins, "invalid options field");
                    msgpack_unpacked_destroy(&result);
                    msgpack_unpacker_free(unp);
                    flb_sds_destroy(out_tag);

                    return -1;
                }

                /* Process array */
                ret = 0;

                for(index = 0 ;
                    index < entry.via.array.size &&
                    ret == 0 ;
                    index++) {
                    ret = fw_process_forward_mode_entry(
                            conn,
                            out_tag, flb_sds_len(out_tag),
                            &entry.via.array.ptr[index],
                            chunk_id);
                }

                if (chunk_id != -1) {
                    msgpack_object options;
                    msgpack_object chunk;

                    options = root.via.array.ptr[2];
                    chunk = options.via.map.ptr[chunk_id].val;

                    send_ack(conn->in, conn, chunk);
                }
            }
            else if (entry.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
                     entry.type == MSGPACK_OBJECT_EXT) {
                /*
                 * Forward format 2 (message mode) : [tag, time, map, ...]
                 */
                map = root.via.array.ptr[2];
                if (map.type != MSGPACK_OBJECT_MAP) {
                    flb_plg_warn(ctx->ins, "invalid data format, map expected");
                    msgpack_unpacked_destroy(&result);
                    msgpack_unpacker_free(unp);
                    flb_sds_destroy(out_tag);
                    return -1;
                }

                /* Check for options */
                chunk_id = -1;
                ret = get_options_chunk(&root, 3, &chunk_id);
                if (ret == -1) {
                    flb_plg_debug(ctx->ins, "invalid options field");
                    msgpack_unpacked_destroy(&result);
                    msgpack_unpacker_free(unp);
                    flb_sds_destroy(out_tag);
                    return -1;
                }

                metadata_id = -1;
                ret = get_options_metadata(&root, 3, &metadata_id);
                if (ret == -1) {
                    flb_plg_debug(ctx->ins, "invalid options field");
                    msgpack_unpacked_destroy(&result);
                    msgpack_unpacker_free(unp);
                    flb_sds_destroy(out_tag);
                    return -1;
                }

                /* Process map */
                fw_process_message_mode_entry(
                    conn->in, conn,
                    out_tag, flb_sds_len(out_tag),
                    &root, &entry, &map, chunk_id,
                    metadata_id);

                c++;
            }
            else if (entry.type == MSGPACK_OBJECT_STR ||
                     entry.type == MSGPACK_OBJECT_BIN) {
                /* PackedForward Mode */
                const char *data = NULL;
                size_t len = 0;

                /* Check for options */
                chunk_id = -1;
                ret = get_options_chunk(&root, 2, &chunk_id);
                if (ret == -1) {
                    flb_plg_debug(ctx->ins, "invalid options field");
                    msgpack_unpacked_destroy(&result);
                    msgpack_unpacker_free(unp);
                    flb_sds_destroy(out_tag);
                    return -1;
                }

                if (entry.type == MSGPACK_OBJECT_STR) {
                    data = entry.via.str.ptr;
                    len = entry.via.str.size;
                }
                else if (entry.type == MSGPACK_OBJECT_BIN) {
                    data = entry.via.bin.ptr;
                    len = entry.via.bin.size;
                }

                if (data) {
                    ret = is_gzip_compressed(root.via.array.ptr[2]);
                    if (ret == -1) {
                        flb_plg_error(ctx->ins, "invalid 'compressed' option");
                        msgpack_unpacked_destroy(&result);
                        msgpack_unpacker_free(unp);
                        flb_sds_destroy(out_tag);
                        return -1;
                    }

                    if (ret == FLB_TRUE) {
                        ret = flb_gzip_uncompress((void *) data, len,
                                                  &gz_data, &gz_size);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins, "gzip uncompress failure");
                            msgpack_unpacked_destroy(&result);
                            msgpack_unpacker_free(unp);
                            flb_sds_destroy(out_tag);
                            return -1;
                        }

                        /* Append uncompressed data */
                        flb_input_log_append(conn->in,
                                             out_tag, flb_sds_len(out_tag),
                                             gz_data, gz_size);
                        flb_free(gz_data);
                    }
                    else {
                        event_type = FLB_EVENT_TYPE_LOGS;
                        if (contain_options) {
                            ret = get_chunk_event_type(ins, root.via.array.ptr[2]);
                            if (ret == -1) {
                                msgpack_unpacked_destroy(&result);
                                msgpack_unpacker_free(unp);
                                flb_sds_destroy(out_tag);
                                return -1;
                            }
                            event_type = ret;
                        }

                        if (event_type == FLB_EVENT_TYPE_LOGS) {
                            flb_input_log_append(conn->in,
                                                 out_tag, flb_sds_len(out_tag),
                                                 data, len);
                        }
                        else if (event_type == FLB_EVENT_TYPE_METRICS) {
                            ret = cmt_decode_msgpack_create(&cmt, (char *) data, len, &off);
                            if (ret == -1) {
                                msgpack_unpacked_destroy(&result);
                                msgpack_unpacker_free(unp);
                                flb_sds_destroy(out_tag);
                                return -1;
                            }
                            flb_input_metrics_append(conn->in,
                                                     out_tag, flb_sds_len(out_tag),
                                                     cmt);
                        }
                        else if (event_type == FLB_EVENT_TYPE_TRACES) {
                            off = 0;
                            ret = ctr_decode_msgpack_create(&ctr, (char *) data, len, &off);
                            if (ret == -1) {
                                msgpack_unpacked_destroy(&result);
                                msgpack_unpacker_free(unp);
                                flb_sds_destroy(out_tag);
                                return -1;
                            }

                            flb_input_trace_append(ins,
                                                   out_tag, flb_sds_len(out_tag),
                                                   ctr);
                        }
                    }

                    /* Handle ACK response */
                    if (chunk_id != -1) {
                        chunk = root.via.array.ptr[2].via.map.ptr[chunk_id].val;
                        send_ack(ctx->ins, conn, chunk);
                    }
                }
            }
            else {
                flb_plg_warn(ctx->ins, "invalid data format, type=%i",
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
    flb_sds_destroy(out_tag);

    switch (ret) {
    case MSGPACK_UNPACK_EXTRA_BYTES:
        flb_plg_error(ctx->ins, "MSGPACK_UNPACK_EXTRA_BYTES");
        return -1;
    case MSGPACK_UNPACK_CONTINUE:
        flb_plg_trace(ctx->ins, "MSGPACK_UNPACK_CONTINUE");
        return 1;
    case MSGPACK_UNPACK_PARSE_ERROR:
        flb_plg_debug(ctx->ins, "err=MSGPACK_UNPACK_PARSE_ERROR");
        return -1;
    case MSGPACK_UNPACK_NOMEM_ERROR:
        flb_plg_error(ctx->ins, "err=MSGPACK_UNPACK_NOMEM_ERROR");
        return -1;
    };

    return 0;
}
