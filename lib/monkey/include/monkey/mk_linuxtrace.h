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

#ifdef LINUX_TRACE

#undef  TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER monkey

#if !defined(_MK_LINUXTRACE_PROVIDER_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _MK_LINUXTRACE_PROVIDER_H
#include <lttng/tracepoint.h>

/* Trace point for epoll(2) events */
TRACEPOINT_EVENT(
                 monkey,
                 epoll,
                 TP_ARGS(int, fd,
                         char *, text),
                 TP_FIELDS(
                           ctf_integer(int, fd, fd)
                           ctf_string(event, text)
                           )
                 )

TRACEPOINT_EVENT(
                 monkey,
                 epoll_state,
                 TP_ARGS(int, fd,
                         int, mode,
                         char *, text),
                 TP_FIELDS(
                           ctf_integer(int, fd, fd)
                           ctf_string(event, text)
                           )
                 )

TRACEPOINT_EVENT(
                 monkey,
                 scheduler,
                 TP_ARGS(int, fd,
                         char *, text),
                 TP_FIELDS(ctf_integer(int, fd, fd)
                           ctf_string(event, text))
                 )

#endif

#undef  TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./monkey/mk_linuxtrace.h"

#include <lttng/tracepoint-event.h>

/* Monkey Linux Trace helper macros */
#define MK_LT_EPOLL(fd, event) tracepoint(monkey, epoll, fd, event)
#define MK_LT_EPOLL_STATE(fd, mode, event) \
  tracepoint(monkey, epoll_state, fd, mode, event)
#define MK_LT_SCHED(fd, event) tracepoint(monkey, scheduler, fd, event)

#else /* NO LINUX_TRACE */

#define MK_LT_EPOLL(fd, event) do {} while(0)
#define MK_LT_EPOLL_STATE(fd, mode, event) do{} while(0)
#define MK_LT_SCHED(fd, event) do {} while(0)
#endif
