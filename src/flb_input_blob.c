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


#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input_blob.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_pack.h>

#include <sys/stat.h>

int flb_input_blob_file_get_info(msgpack_object map, cfl_sds_t *source, cfl_sds_t *file_path, size_t *size)
{
    cfl_sds_t tmp_source;
    cfl_sds_t tmp_file_path;
    msgpack_object o;
    size_t tmp_size;

    if (map.type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    if (map.via.map.size < 3) {
        return -1;
    }

    /* get file_path */
    o = map.via.map.ptr[0].key;
    if (o.type != MSGPACK_OBJECT_STR) {
        return -1;
    }
    if (o.via.str.size != 9 || strncmp(o.via.str.ptr, "file_path", 9) != 0) {
        return -1;
    }

    o = map.via.map.ptr[0].val;
    if (o.type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    tmp_file_path = cfl_sds_create_len(o.via.str.ptr, o.via.str.size);
    if (tmp_file_path == NULL) {
        return -1;
    }

    /* get size */
    o = map.via.map.ptr[1].key;
    if (o.type != MSGPACK_OBJECT_STR) {
        cfl_sds_destroy(tmp_file_path);
        return -1;
    }
    if (o.via.str.size != 4 || strncmp(o.via.str.ptr, "size", 4) != 0) {
        cfl_sds_destroy(tmp_file_path);
        return -1;
    }

    o = map.via.map.ptr[1].val;
    if (o.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        cfl_sds_destroy(tmp_file_path);
        return -1;
    }

    tmp_size = o.via.u64;

    /* get source plugin */
    o = map.via.map.ptr[2].key;
    if (o.type != MSGPACK_OBJECT_STR) {
        cfl_sds_destroy(tmp_file_path);
        return -1;
    }
    if (o.via.str.size != 6 || strncmp(o.via.str.ptr, "source", 6) != 0) {
        cfl_sds_destroy(tmp_file_path);
        return -1;
    }

    o = map.via.map.ptr[2].val;
    if (o.type != MSGPACK_OBJECT_STR) {
        cfl_sds_destroy(tmp_file_path);
        return -1;
    }

    tmp_source = cfl_sds_create_len(o.via.str.ptr, o.via.str.size);
    if (tmp_source == NULL) {
        cfl_sds_destroy(tmp_file_path);
        return -1;
    }

    *size = tmp_size;
    *file_path = tmp_file_path;
    *source = tmp_source;

    return 0;
}

int flb_input_blob_file_register(struct flb_input_instance *ins,
                                 struct flb_log_event_encoder *encoder,
                                 const char *tag, size_t tag_len,
                                 char *file_path, size_t size)
{
    int ret;
    struct stat st;

    /* check if the file is readable */
    ret = access(file_path, R_OK);
    if (ret == -1) {
        flb_plg_error(ins, "file %s is not readable", file_path);
        return -1;
    }

    /* get file information */
    ret = stat(file_path, &st);
    if (ret == -1) {
        flb_errno();
        return -1;
    }

    /* is the requested file size valid ? */
    if (size > st.st_size) {
        flb_error("[blob file registration] requested size %zu for file %s is greater than the file size %zu",
                  size, file_path, st.st_size);
        return -1;
    }

    /* Encode the blob file info in msgpack by using the log encoder wrapper */
    ret = flb_log_event_encoder_begin_record(encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[blob file registration] could not begin blob record");
        return -1;
    }

    /* add timestamp */
    ret = flb_log_event_encoder_set_current_timestamp(encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[blob file registration] could not set timestamp");
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(encoder, "file_path");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[blob file registration] could not append path");
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(encoder, file_path);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[blob file registration] could not append path");
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(encoder, "size");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[blob file registration] could not append path");
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_uint64(encoder, size);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[blob file registration] could not append size");
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(encoder, "source");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[blob file registration] could not append path");
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(encoder, (char *) flb_input_name(ins));
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[blob file registration] could not append source plugin name");
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[blob file registration] could not commit record");
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    /* register entry as a chunk */
    ret = flb_input_chunk_append_raw(ins, FLB_INPUT_BLOBS, 0,
                                     tag, tag_len,
                                     encoder->output_buffer,
                                     encoder->output_length);
    if (ret != 0) {
        flb_error("[blob file registration] could not append blob record");
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    flb_log_event_encoder_reset(encoder);
    return ret;
}

void flb_input_blob_delivery_notification_destroy(void *instance)
{
    struct flb_blob_delivery_notification *local_instance;

    local_instance = (struct flb_blob_delivery_notification *) instance;

    if (local_instance->path != NULL) {
        cfl_sds_destroy(local_instance->path);
    }
}
