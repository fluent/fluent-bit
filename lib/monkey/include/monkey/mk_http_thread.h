/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2016 Monkey Software LLC <eduardo@monkey.io>
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

#ifndef MK_HTTP_THREAD_H
#define MK_HTTP_THREAD_H

#include <monkey/mk_http.h>
#include <monkey/mk_thread.h>
#include <monkey/mk_vhost.h>

#define MK_HTTP_THREAD_LIB     0
#define MK_HTTP_THREAD_PLUGIN  1

struct mk_http_thread {
    int close;                        /* Close TCP connection ?  */
    struct mk_http_session *session;  /* HTTP session            */
    struct mk_http_request *request;  /* HTTP request            */
    struct mk_thread       *parent;   /* Parent thread           */
    struct mk_list _head;             /* Link to worker->threads */
};

extern MK_TLS_DEFINE(struct mk_http_libco_params, mk_http_thread_libco_params);
extern MK_TLS_DEFINE(struct mk_thread,            mk_thread);

static MK_INLINE void mk_http_thread_resume(struct mk_http_thread *mth)
{
    mk_thread_resume(mth->parent);
}

void mk_http_thread_initialize_tls();

struct mk_http_thread *mk_http_thread_create(int type,
                                             struct mk_vhost_handler *handler,
                                             struct mk_http_session *session,
                                             struct mk_http_request *request,
                                             int n_params,
                                             struct mk_list *params);
int mk_http_thread_destroy(struct mk_http_thread *mth);

int mk_http_thread_event(struct mk_event *event);

int mk_http_thread_start(struct mk_http_thread *mth);
int mk_http_thread_purge(struct mk_http_thread *mth, int close);

#endif
