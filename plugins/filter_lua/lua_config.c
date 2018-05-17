/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>

#include "lua_config.h"

#include <fcntl.h>
#include <unistd.h>

struct lua_filter *lua_config_create(struct flb_filter_instance *ins,
                                     struct flb_config *config)
{
    int ret;
    char *tmp;
    (void) config;
    struct lua_filter *lf;

    /* Allocate context */
    lf = flb_calloc(1, sizeof(struct lua_filter));
    if (!lf) {
        flb_errno();
        return NULL;
    }

    /* Config: script */
    tmp = flb_filter_get_property("script", ins);
    if (!tmp) {
        flb_error("[filter_lua] no script path defined");
        flb_free(lf);
        return NULL;
    }

    /* Validate path */
    ret = access(tmp, R_OK);
    if (ret == -1) {
        flb_error("[filter_lua] cannot access script '%s'", tmp);
        flb_free(lf);
        return NULL;
    }

    lf->script = flb_sds_create(tmp);
    if (!lf->script) {
        flb_error("[filter_lua] could not allocate string");
        flb_free(lf);
        return NULL;
    }

    /* Config: call */
    tmp = flb_filter_get_property("call", ins);
    if (!tmp) {
        flb_error("[filter_lua] no call property defined");
        lua_config_destroy(lf);
        return NULL;
    }

    lf->call = flb_sds_create(tmp);
    if (!lf->call) {
        flb_error("[filter_lua] could not allocate call");
        lua_config_destroy(lf);
        return NULL;
    }

    lf->buffer = flb_sds_create_size(LUA_BUFFER_CHUNK);
    if (!lf->buffer) {
        flb_error("[filter_lua] could not allocate decode buffer");
        lua_config_destroy(lf);
        return NULL;
    }

    return lf;
}

void lua_config_destroy(struct lua_filter *lf)
{
    if (!lf) {
        return;
    }

    if (lf->script) {
        flb_sds_destroy(lf->script);
    }
    if (lf->call) {
        flb_sds_destroy(lf->call);
    }
    if (lf->buffer) {
        flb_sds_destroy(lf->buffer);
    }
    flb_free(lf);
}
