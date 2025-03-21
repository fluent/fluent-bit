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

#ifndef MK_SCHEDULER_TLS_H
#define MK_SCHEDULER_TLS_H

#ifdef MK_HAVE_C_TLS  /* Use Compiler Thread Local Storage (TLS) */

__thread struct rb_root *mk_tls_sched_cs;
__thread struct mk_list *mk_tls_sched_cs_incomplete;
__thread struct mk_sched_notif *mk_tls_sched_worker_notif;
__thread struct mk_sched_worker *mk_tls_sched_worker_node;

#else

pthread_key_t mk_tls_sched_cs;
pthread_key_t mk_tls_sched_cs_incomplete;
pthread_key_t mk_tls_sched_worker_notif;
pthread_key_t mk_tls_sched_worker_node;

#endif

#endif
