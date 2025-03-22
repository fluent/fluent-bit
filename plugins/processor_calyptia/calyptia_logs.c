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

#include <fluent-bit/flb_lua.h>
#include <fluent-bit/flb_luajit.h>

#include <fluent-bit/flb_processor_plugin.h>

#include "calyptia_logs.h"
#include "calyptia_defs.h"
#include "calyptia_logs_to_lua.h"
#include "calyptia_logs_from_lua.h"

static void clear_logs(struct flb_mp_chunk_cobj *chunk_cobj)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct flb_mp_chunk_record *record = NULL;

    cfl_list_foreach_safe(head, tmp, &chunk_cobj->records)
    {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        if (record->cobj_metadata) {
          cfl_object_destroy(record->cobj_metadata);
        }
        if (record->cobj_record) {
          cfl_object_destroy(record->cobj_record);
        }
        cfl_list_del(&record->_head);
        flb_free(record);
    }
}

int calyptia_process_logs(struct flb_processor_instance *ins, void *chunk_data,
                          const char *tag, int tag_len)
{
    struct calyptia_context *ctx;
    struct flb_mp_chunk_cobj *chunk_cobj;
    int ret;
    int l_code;

    ctx = ins->context;
    chunk_cobj = (struct flb_mp_chunk_cobj *) chunk_data;

    ret = FLB_PROCESSOR_SUCCESS;
    /* push the lua helper */
    lua_pushlightuserdata(ctx->lua->state, LUA_LOGS_HELPER_KEY);
    lua_gettable(ctx->lua->state, LUA_REGISTRYINDEX);
    /* push the lua callback */
    lua_getglobal(ctx->lua->state, ctx->call);
    /* push the tag */
    lua_pushlstring(ctx->lua->state, tag, tag_len);
    if (calyptia_logs_to_lua(ctx->lua->state, chunk_data)) {
        flb_plg_error(ctx->ins, "Failed to encode logs");
        return FLB_PROCESSOR_FAILURE;
    }

    ret = lua_pcall(ctx->lua->state, 3, 3, 0);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error code %d: %s", ret,
                      lua_tostring(ctx->lua->state, -1));
        lua_pop(ctx->lua->state, 1);
        return FLB_PROCESSOR_FAILURE;
    }

    /* index -2 is the "ingest" object, for which handling will only be
     * implemented in the future */
    l_code = (int) lua_tointeger(ctx->lua->state, -3);
    if (l_code == -1) {
      clear_logs(chunk_cobj);
    }
    else if (l_code == 0) {
        /* nothing to do */
    }
    else if (l_code != 1) {
        flb_plg_error(ctx->ins, "invalid return code %d", l_code);
        ret = FLB_PROCESSOR_FAILURE;
    }
    else {
        clear_logs(chunk_cobj);
        if (calyptia_logs_from_lua(ins, ctx->lua->state, chunk_cobj)) {
            flb_plg_error(ctx->ins, "Failed to decode logs from lua");
            ret = FLB_PROCESSOR_FAILURE;
        }
    }

    /* clear lua stack */
    lua_settop(ctx->lua->state, 0);
    return ret;
}
