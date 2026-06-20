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

#include <fluent-bit/flb_output_plugin.h>

#include "stackdriver.h"
#include "stackdriver_helper.h"
#include "stackdriver_operation.h"

typedef enum {
    NO_OPERATION = 1,
    OPERATION_EXISTED = 2
} operation_status;

void add_operation_field(flb_sds_t *operation_id, flb_sds_t *operation_producer,
                         int *operation_first, int *operation_last,
                         msgpack_packer *mp_pck)
{
    msgpack_pack_str(mp_pck, 9);
    msgpack_pack_str_body(mp_pck, "operation", 9);

    msgpack_pack_map(mp_pck, 4);

    msgpack_pack_str(mp_pck, OPERATION_ID_SIZE);
    msgpack_pack_str_body(mp_pck, OPERATION_ID, OPERATION_ID_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(*operation_id));
    msgpack_pack_str_body(mp_pck, *operation_id, flb_sds_len(*operation_id));

    msgpack_pack_str(mp_pck, OPERATION_PRODUCER_SIZE);
    msgpack_pack_str_body(mp_pck, OPERATION_PRODUCER, OPERATION_PRODUCER_SIZE);
    msgpack_pack_str(mp_pck, flb_sds_len(*operation_producer));
    msgpack_pack_str_body(mp_pck, *operation_producer,
                          flb_sds_len(*operation_producer));

    msgpack_pack_str(mp_pck, OPERATION_FIRST_SIZE);
    msgpack_pack_str_body(mp_pck, OPERATION_FIRST, OPERATION_FIRST_SIZE);
    if (*operation_first == FLB_TRUE) {
        msgpack_pack_true(mp_pck);
    }
    else {
        msgpack_pack_false(mp_pck);
    }

    msgpack_pack_str(mp_pck, OPERATION_LAST_SIZE);
    msgpack_pack_str_body(mp_pck, OPERATION_LAST, OPERATION_LAST_SIZE);
    if (*operation_last == FLB_TRUE) {
        msgpack_pack_true(mp_pck);
    }
    else {
        msgpack_pack_false(mp_pck);
    }
}

/* Return true if operation extracted */
int extract_operation(flb_sds_t *operation_id, flb_sds_t *operation_producer,
                      int *operation_first, int *operation_last,
                      msgpack_object *obj, int *extra_subfields)
{
    operation_status op_status = NO_OPERATION;
    msgpack_object_kv *p;
    msgpack_object_kv *pend;
    msgpack_object_kv *tmp_p;
    msgpack_object_kv *tmp_pend;

    if (obj->via.map.size == 0) {
        return FLB_FALSE;
    }
    p = obj->via.map.ptr;
    pend = obj->via.map.ptr + obj->via.map.size;

    for (; p < pend && op_status == NO_OPERATION; ++p) {

        if (p->val.type != MSGPACK_OBJECT_MAP
            || !validate_key(p->key, OPERATION_FIELD_IN_JSON,
                             OPERATION_KEY_SIZE)) {
            continue;
        }

        op_status = OPERATION_EXISTED;
        msgpack_object sub_field = p->val;

        tmp_p = sub_field.via.map.ptr;
        tmp_pend = sub_field.via.map.ptr + sub_field.via.map.size;

        /* Validate the subfields of operation */
        for (; tmp_p < tmp_pend; ++tmp_p) {
            if (tmp_p->key.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (validate_key(tmp_p->key, OPERATION_ID, OPERATION_ID_SIZE)) {
                try_assign_subfield_str(tmp_p->val, operation_id);
            }
            else if (validate_key(tmp_p->key, OPERATION_PRODUCER,
                                  OPERATION_PRODUCER_SIZE)) {
                try_assign_subfield_str(tmp_p->val, operation_producer);
            }
            else if (validate_key(tmp_p->key, OPERATION_FIRST, OPERATION_FIRST_SIZE)) {
                try_assign_subfield_bool(tmp_p->val, operation_first);
            }
            else if (validate_key(tmp_p->key, OPERATION_LAST, OPERATION_LAST_SIZE)) {
                try_assign_subfield_bool(tmp_p->val, operation_last);
            }
            else {
                *extra_subfields += 1;
            }
        }
    }

    return op_status == OPERATION_EXISTED;
}

void pack_extra_operation_subfields(msgpack_packer *mp_pck,
                                    msgpack_object *operation, int extra_subfields) {
    msgpack_object_kv *p = operation->via.map.ptr;
    msgpack_object_kv *const pend = operation->via.map.ptr + operation->via.map.size;

    msgpack_pack_map(mp_pck, extra_subfields);

    for (; p < pend; ++p) {
        if (validate_key(p->key, OPERATION_ID, OPERATION_ID_SIZE)
            || validate_key(p->key, OPERATION_PRODUCER, OPERATION_PRODUCER_SIZE)
            || validate_key(p->key, OPERATION_FIRST, OPERATION_FIRST_SIZE)
            || validate_key(p->key, OPERATION_LAST, OPERATION_LAST_SIZE)) {
            continue;
        }

        msgpack_pack_object(mp_pck, p->key);
        msgpack_pack_object(mp_pck, p->val);
    }
}
