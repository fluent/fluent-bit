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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_luajit.h>

struct flb_luajit *flb_luajit_create(struct flb_config *config)
{
    struct flb_luajit *lj;

    lj = flb_malloc(sizeof(struct flb_luajit));
    if (!lj) {
        flb_errno();
        return NULL;
    }

    lj->state = luaL_newstate();
    if (!lj->state) {
        flb_error("[luajit] error creating new context");
        flb_free(lj);
        return NULL;
    }
    luaL_openlibs(lj->state);
    lj->config = config;
    mk_list_add(&lj->_head, &config->luajit_list);

    return lj;
}

int flb_luajit_load_script(struct flb_luajit *lj, char *script)
{
    int ret;

    ret = luaL_loadfile(lj->state, script);
    if (ret != 0) {
        flb_error("[luajit] error loading script: %s",
                  lua_tostring(lj->state, -1));
        return -1;
    }

    return 0;
}

int flb_luajit_load_buffer(struct flb_luajit *lj, char *string, size_t len, char *name)
{
    int ret;

    ret = luaL_loadbuffer(lj->state, string, len, name);
    if (ret != 0) {
        flb_error("[luajit] error loading buffer: %s",
                  lua_tostring(lj->state, -1));
        return -1;
    }

    return 0;
}

void flb_luajit_destroy(struct flb_luajit *lj)
{
    lua_close(lj->state);
    mk_list_del(&lj->_head);
    flb_free(lj);
}

int flb_luajit_destroy_all(struct flb_config *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_luajit *lj;

    mk_list_foreach_safe(head, tmp, &ctx->luajit_list) {
        lj = mk_list_entry(head, struct flb_luajit, _head);
        flb_luajit_destroy(lj);
        c++;
    }

    return c;
}
