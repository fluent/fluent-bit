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

#ifndef FLB_CALYPTIA_DEFS_H
#define FLB_CALYPTIA_DEFS_H

#include <fluent-bit/flb_lua.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_processor_plugin.h>

extern char calyptia_processor_lua_helpers[];

#define LUA_LOGS_HELPER_KEY (calyptia_processor_lua_helpers + 1)
#define LUA_METRICS_HELPER_KEY (calyptia_processor_lua_helpers + 2)
#define LUA_TRACES_HELPER_KEY (calyptia_processor_lua_helpers + 3)

struct calyptia_context {
    flb_sds_t code;                     /* lua script source code */
    flb_sds_t script;                   /* lua script path */
    flb_sds_t call;                     /* lua callback to process the event */
    struct flb_luajit *lua;             /* state context   */
    struct flb_processor_instance *ins; /* processor instance */
    bool disable_warnings;              /* disable warnings from lua helpers */
    struct cfl_variant *opts;           /* arbitrary object passed to lua script */
};


#endif
