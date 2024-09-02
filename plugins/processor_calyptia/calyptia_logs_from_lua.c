/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_processor_plugin.h>

#include "calyptia_logs_from_lua.h"
#include "lua_to_cfl.h"

int calyptia_logs_from_lua(struct flb_processor_instance *ins, lua_State *L,
                           struct flb_mp_chunk_cobj *chunk_cobj)
{
    int i;
    int logs_length, metadata_length, timestamps_length;
    struct flb_mp_chunk_record *record;

    if (lua_type(L, -1) != LUA_TTABLE) {
        flb_plg_error(ins, "expected events object");
        return -1;
    }

    lua_getfield(L, -1, "logs");
    if (lua_type(L, -1) != LUA_TTABLE) {
        flb_plg_error(ins, "expected logs object");
        return -1;
    }

    lua_getfield(L, -2, "metadata");
    if (lua_type(L, -1) != LUA_TTABLE) {
        flb_plg_error(ins, "expected metadata object");
        return -1;
    }

    lua_getfield(L, -3, "timestamps");
    if (lua_type(L, -1) != LUA_TTABLE) {
        flb_plg_error(ins, "expected timestamps object");
        return -1;
    }

    logs_length = lua_objlen(L, -3);
    metadata_length = lua_objlen(L, -2);
    timestamps_length = lua_objlen(L, -1);

    if (logs_length != metadata_length || logs_length != timestamps_length) {
        flb_plg_error(ins, "logs, metadata, and timestamps must have the same length");
        return -1;
    }

    for (i = 1; i <= logs_length; i++) {
        record = flb_mp_chunk_record_create(chunk_cobj);
        if (!record) {
            flb_plg_error(ins, "failed to create record");
            return -1;
        }

        record->cobj_record = cfl_object_create();
        if (!record->cobj_record) {
            flb_plg_error(ins, "failed to create record object");
            return -1;
        }

        record->cobj_metadata = cfl_object_create();
        if (!record->cobj_metadata) {
            flb_plg_error(ins, "failed to create metadata object");
            return -1;
        }

        memset(&record->event, 0, sizeof(record->event));

        /* get the timestamp */
        lua_rawgeti(L, -1, i);
        flb_time_from_double(&record->event.timestamp, lua_to_double(L, -1));
        lua_pop(L, 1);

        /* get the metadata */
        lua_rawgeti(L, -2, i);
        record->cobj_metadata->variant = lua_to_variant(L, -1);
        record->cobj_metadata->type = CFL_OBJECT_VARIANT;
        lua_pop(L, 1);

        /* get the log */
        lua_rawgeti(L, -3, i);
        record->cobj_record->variant = lua_to_variant(L, -1);
        record->cobj_record->type = CFL_OBJECT_VARIANT;
        lua_pop(L, 1);

        cfl_list_add(&record->_head, &chunk_cobj->records);
    }

    /* pop all */
    lua_pop(L, 3);

    return 0;
}
