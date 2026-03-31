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

#ifndef FLB_LUA_CONFIG_H
#define FLB_LUA_CONFIG_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_lua.h>

#define LUA_BUFFER_CHUNK    1024 * 8  /* 8K should be enough to get started */

struct lua_filter {
    flb_sds_t code;                   /* lua script source code */
    flb_sds_t script;                 /* lua script path */
    flb_sds_t call;                   /* function name   */
    flb_sds_t buffer;                 /* json dec buffer */
    int    protected_mode;            /* exec lua function in protected mode */
    int    time_as_table;             /* timestamp as a Lua table */
    int    enable_flb_null;           /* Use flb_null in Lua */
    struct flb_lua_l2c_config l2cc;   /* lua -> C config */
    struct flb_luajit *lua;           /* state context   */
    struct flb_filter_instance *ins;  /* filter instance */
    flb_sds_t packbuf;                /* dynamic buffer used for mpack write */
    int cb_args;                      /* number of callback arguments */
    int cb_expected_returns;          /* expected return values from Lua */

};

struct lua_filter *lua_config_create(struct flb_filter_instance *ins,
                                     struct flb_config *config);
void lua_config_destroy(struct lua_filter *lf);

#endif
