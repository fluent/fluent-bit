/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#ifndef MONKEY_PLUGIN_API_H
#define MONKEY_PLUGIN_API_H

#define _GNU_SOURCE

/* Monkey Headers */
#include <monkey/monkey.h>
#include <monkey/mk_socket.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_http.h>
#include <monkey/mk_socket.h>
#include <monkey/mk_kernel.h>
#include <monkey/mk_core.h>

/* General Headers */
#include <errno.h>

/* global vars */
struct plugin_api *mk_api;

pthread_key_t MK_EXPORT _mkp_data;

#define MONKEY_PLUGIN(a, b, c, d)                   \
    struct mk_plugin_info MK_EXPORT _plugin_info = {a, b, c, d}

#ifdef MK_TRACE
#undef MK_TRACE
#endif

#ifdef TRACE

#define MK_TRACE(api, ...)                  \
    api->trace("pl",                        \
                MK_TRACE_PLUGIN,            \
                __FUNCTION__,               \
                __FILENAME__,               \
                __LINE__,                   \
                __VA_ARGS__)
#define PLUGIN_TRACE  MK_TRACE
#else
#define MK_TRACE(...) do {} while(0)
#define PLUGIN_TRACE(...) do{} while(0)
#endif

/*
 * Redefine messages macros
 */

#undef  mk_info_ex
#define mk_info_ex(api, ...) api->_error(MK_INFO, __VA_ARGS__)

#undef  mk_err_ex
#define mk_err_ex(api, ...) api->_error(MK_ERR, __VA_ARGS__)

#undef  mk_warn_ex
#define mk_warn_ex(api, ...) api->_error(MK_WARN, __VA_ARGS__)

#undef  mk_bug_ex
#define mk_bug_ex(api, condition) do {                  \
        if (mk_unlikely((condition)!=0)) {         \
            api->_error(MK_BUG, "[%s] Bug found in %s() at %s:%d",    \
                        _plugin_info.shortname, __FUNCTION__, __FILE__, __LINE__); \
            abort();                                                    \
        }                                                               \
    } while(0)

#undef  mk_info
#define mk_info(...) mk_info_ex(mk_api, __VA_ARGS__)

#undef  mk_err
#define mk_err(...) mk_error_ex(mk_api, __VA_ARGS__)

#undef  mk_warn
#define mk_warn(...) mk_error_ex(mk_api, __VA_ARGS__)

#undef  mk_bug
#define mk_bug(condition) mk_bug_ex(mk_api, condition)

#endif

