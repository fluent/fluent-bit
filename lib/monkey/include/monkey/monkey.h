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

#ifndef MK_MONKEY_H
#define MK_MONKEY_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <monkey/mk_core.h>

#ifdef LINUX_TRACE
#define TRACEPOINT_CREATE_PROBES
#define TRACEPOINT_DEFINE
#include <monkey/mk_linuxtrace.h>
#endif

#include <monkey/mk_core.h>
#include <monkey/mk_server.h>
#include <monkey/mk_kernel.h>
#include <monkey/mk_user.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_cache.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_env.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_config.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_tls.h>

/* Max Path lenth */
#define MK_MAX_PATH 1024

/* Send_Header(...,int cgi) */
#define SH_NOCGI 0
#define SH_CGI 1

/* Monkey Protocol */
extern const mk_ptr_t mk_monkey_protocol;

struct mk_server *mk_server_init();

void mk_server_info();
int mk_server_setup(struct mk_server *server);
void mk_thread_keys_init();
void mk_exit_all(struct mk_server *config);

#endif
