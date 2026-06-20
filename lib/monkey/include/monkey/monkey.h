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

void mk_server_info(struct mk_server *server);
int mk_server_setup(struct mk_server *server);
void mk_thread_keys_init();
void mk_exit_all(struct mk_server *config);

#endif
