/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ------------------
 *  Copyright (C) 2001-2015, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public  License as published
 *  by the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 *  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 *  License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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

