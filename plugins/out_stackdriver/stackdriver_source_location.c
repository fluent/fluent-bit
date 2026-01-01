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
#include "stackdriver.h"
#include "stackdriver_helper.h"
#include "stackdriver_source_location.h"

typedef enum {
    NO_SOURCELOCATION = 1,
    SOURCELOCATION_EXISTED = 2
} source_location_status;


void add_source_location_field(flb_sds_t *source_location_file,
                               int64_t source_location_line,
                               flb_sds_t *source_location_function,
                               msgpack_packer *mp_pck)
{
    msgpack_pack_str(mp_pck, 14);
    msgpack_pack_str_body(mp_pck, "sourceLocation", 14);
    msgpack_pack_map(mp_pck, 3);

    msgpack_pack_str(mp_pck, SOURCE_LOCATION_FILE_SIZE);
    msgpack_pack_str_body(mp_pck, SOURCE_LOCATION_FILE, SOURCE_LOCATION_FILE_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(*source_location_file));
    msgpack_pack_str_body(mp_pck, *source_location_file,
                          flb_sds_len(*source_location_file));

    msgpack_pack_str(mp_pck, SOURCE_LOCATION_LINE_SIZE);
    msgpack_pack_str_body(mp_pck, SOURCE_LOCATION_LINE, SOURCE_LOCATION_LINE_SIZE);
    msgpack_pack_int64(mp_pck, source_location_line);

    msgpack_pack_str(mp_pck, SOURCE_LOCATION_FUNCTION_SIZE);
    msgpack_pack_str_body(mp_pck, SOURCE_LOCATION_FUNCTION,
                          SOURCE_LOCATION_FUNCTION_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(*source_location_function));
    msgpack_pack_str_body(mp_pck, *source_location_function,
                          flb_sds_len(*source_location_function));
}

/* Return FLB_TRUE if sourceLocation extracted */
int extract_source_location(flb_sds_t *source_location_file,
                            int64_t *source_location_line,
                            flb_sds_t *source_location_function,
                            msgpack_object *obj, int *extra_subfields)
{
    source_location_status op_status = NO_SOURCELOCATION;
    msgpack_object_kv *p;
    msgpack_object_kv *pend;
    msgpack_object_kv *tmp_p;
    msgpack_object_kv *tmp_pend;

    if (obj->via.map.size == 0) {
        return FLB_FALSE;
    }
    p = obj->via.map.ptr;
    pend = obj->via.map.ptr + obj->via.map.size;

    for (; p < pend && op_status == NO_SOURCELOCATION; ++p) {

        if (p->val.type != MSGPACK_OBJECT_MAP
            || p->key.type != MSGPACK_OBJECT_STR
            || !validate_key(p->key, SOURCELOCATION_FIELD_IN_JSON,
                             SOURCE_LOCATION_SIZE)) {

            continue;
        }

        op_status = SOURCELOCATION_EXISTED;
        msgpack_object sub_field = p->val;

        tmp_p = sub_field.via.map.ptr;
        tmp_pend = sub_field.via.map.ptr + sub_field.via.map.size;

        /* Validate the subfields of sourceLocation */
        for (; tmp_p < tmp_pend; ++tmp_p) {
            if (tmp_p->key.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (validate_key(tmp_p->key,
                             SOURCE_LOCATION_FILE,
                             SOURCE_LOCATION_FILE_SIZE)) {
                try_assign_subfield_str(tmp_p->val, source_location_file);
            }
            else if (validate_key(tmp_p->key,
                                  SOURCE_LOCATION_FUNCTION,
                                  SOURCE_LOCATION_FUNCTION_SIZE)) {
                try_assign_subfield_str(tmp_p->val, source_location_function);
            }
            else if (validate_key(tmp_p->key,
                                  SOURCE_LOCATION_LINE,
                                  SOURCE_LOCATION_LINE_SIZE)) {
                try_assign_subfield_int(tmp_p->val, source_location_line);
            }
            else {
                *extra_subfields += 1;
            }
        }
    }

    return op_status == SOURCELOCATION_EXISTED;
}

void pack_extra_source_location_subfields(msgpack_packer *mp_pck,
                                          msgpack_object *source_location,
                                          int extra_subfields) {
    msgpack_object_kv *p = source_location->via.map.ptr;
    msgpack_object_kv *const pend = source_location->via.map.ptr + source_location->via.map.size;

    msgpack_pack_map(mp_pck, extra_subfields);

    for (; p < pend; ++p) {
        if (validate_key(p->key, SOURCE_LOCATION_FILE, SOURCE_LOCATION_FILE_SIZE)
            || validate_key(p->key, SOURCE_LOCATION_LINE, SOURCE_LOCATION_LINE_SIZE)
            || validate_key(p->key, SOURCE_LOCATION_FUNCTION,
                            SOURCE_LOCATION_FUNCTION_SIZE)) {
            continue;
        }

        msgpack_pack_object(mp_pck, p->key);
        msgpack_pack_object(mp_pck, p->val);
    }
}
