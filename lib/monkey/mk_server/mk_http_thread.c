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

#include <monkey/mk_info.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_thread.h>
#include <monkey/mk_net.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_http_thread.h>

#include <stdlib.h>

/*
 * libco do not support parameters in the entrypoint function due to the
 * complexity of implementation in terms of architecture and compiler, but
 * it provide a workaround using a global structure as a middle entry-point
 * that achieve the same stuff.
 */
struct mk_http_libco_params {
    int type;
    struct mk_vhost_handler *handler;
    struct mk_http_session *session;
    struct mk_http_request *request;
    int n_params;
    struct mk_list *params;
    struct mk_thread *th;
};

pthread_once_t mk_http_thread_initialize_tls_once_flag = PTHREAD_ONCE_INIT;

MK_TLS_DEFINE(struct mk_http_libco_params, mk_http_thread_libco_params);
MK_TLS_DEFINE(struct mk_thread,            mk_thread);

/* This function could return NULL if the process runs out of memory, in that
 * case failure is imminent.
 */
static inline struct mk_http_libco_params *thread_get_libco_params()
{
    struct mk_http_libco_params *libco_params;

    libco_params = MK_TLS_GET(mk_http_thread_libco_params);

    if (libco_params == NULL) {
        libco_params = mk_mem_alloc_z(sizeof(struct mk_http_libco_params));

        if (libco_params == NULL) {
            mk_err("libco thread params could not be allocated.");
        }

        MK_TLS_SET(mk_http_thread_libco_params, libco_params);
    }

    return libco_params;
}

static void mk_http_thread_initialize_tls_once()
{
    MK_TLS_INIT(mk_http_thread_libco_params);
    MK_TLS_INIT(mk_thread);
}

void mk_http_thread_initialize_tls()
{
    pthread_once(&mk_http_thread_initialize_tls_once_flag,
                 mk_http_thread_initialize_tls_once);
}

static inline void thread_cb_init_vars()
{
    struct mk_http_libco_params *libco_params;
    struct mk_vhost_handler     *handler;
    struct mk_http_session      *session;
    struct mk_http_request      *request;
    int                          close;
    int                          type;
    struct mk_http_thread       *mth;
    struct mk_thread            *th;

    libco_params = thread_get_libco_params();

    type = libco_params->type;
    handler = libco_params->handler;
    session = libco_params->session;
    request = libco_params->request;
    th = libco_params->th;

    /*
     * Until this point the th->callee already set the variables, so we
     * wait until the core wanted to resume so we really trigger the
     * output callback.
     */
    co_switch(th->caller);

    if (type == MK_HTTP_THREAD_LIB) {
        /* Invoke the handler callback */
        handler->cb(request, handler->data);

        /*
         * Once the callback finished, we need to sanitize the connection
         * so other further requests can be processed.
         */
        int ret;
        struct mk_sched_worker *sched;
        struct mk_channel *channel;

        channel = request->session->channel;
        sched = mk_sched_get_thread_conf();

        MK_EVENT_NEW(channel->event);
        ret = mk_event_add(sched->loop,
                           channel->fd,
                           MK_EVENT_CONNECTION,
                           MK_EVENT_READ, channel->event);
        if (ret == -1) {
            //return -1;
        }

        /* Save temporal session */
        mth = request->thread;

        /*
         * Finalize request internally, if ret == -1 means we should
         * ask to shutdown the connection.
         */
        ret = mk_http_request_end(session, session->server);
        if (ret == -1) {
            close = MK_TRUE;
        }
        else {
            close = MK_FALSE;
        }
        mk_http_thread_purge(mth, close);

        /* Return control to caller */
        mk_thread_yield(th);
    }
    else if (type == MK_HTTP_THREAD_PLUGIN) {
        /* FIXME: call plugin handler callback with params */
    }
}

static inline void thread_params_set(struct mk_thread *th,
                                     int type,
                                     struct mk_vhost_handler *handler,
                                     struct mk_http_session *session,
                                     struct mk_http_request *request,
                                     int n_params,
                                     struct mk_list *params)
{
    struct mk_http_libco_params *libco_params;

    libco_params = thread_get_libco_params();

    /* Callback parameters in order */
    libco_params->type     = type;
    libco_params->handler  = handler;
    libco_params->session  = session;
    libco_params->request  = request;
    libco_params->n_params = n_params;
    libco_params->params   = params;
    libco_params->th       = th;

    co_switch(th->callee);
}

struct mk_http_thread *mk_http_thread_create(int type,
                                             struct mk_vhost_handler *handler,
                                             struct mk_http_session *session,
                                             struct mk_http_request *request,
                                             int n_params,
                                             struct mk_list *params)
{
    size_t stack_size;
    struct mk_thread *th = NULL;
    struct mk_http_thread *mth;
    struct mk_sched_worker *sched;

    sched = mk_sched_get_thread_conf();
    if (!sched) {
        return NULL;
    }

    th = mk_thread_new(sizeof(struct mk_http_thread), NULL);
    if (!th) {
        return NULL;
    }

    mth = (struct mk_http_thread *) MK_THREAD_DATA(th);
    if (!mth) {
        return NULL;
    }

    mth->session = session;
    mth->request = request;
    mth->parent  = th;
    mth->close   = MK_FALSE;
    request->thread = mth;
    mk_list_add(&mth->_head, &sched->threads);

    th->caller = co_active();
    th->callee = co_create(MK_THREAD_STACK_SIZE,
                           thread_cb_init_vars, &stack_size);

#ifdef MK_HAVE_VALGRIND
    th->valgrind_stack_id = VALGRIND_STACK_REGISTER(th->callee,
                                                    ((char *)th->callee) + stack_size);
#endif

    /* Workaround for makecontext() */
    thread_params_set(th, type, handler, session, request, n_params, params);

    return mth;
}

/*
 * Move a http thread context from sched->thread to sched->threads_purge list.
 * On this way the scheduler will release or reasign the resource later.
 */
int mk_http_thread_purge(struct mk_http_thread *mth, int close)
{
    struct mk_sched_worker *sched;

    sched = mk_sched_get_thread_conf();
    if (!sched) {
        return -1;
    }

    mth->close = close;
    mk_list_del(&mth->_head);
    mk_list_add(&mth->_head, &sched->threads_purge);

    return 0;
}

int mk_http_thread_destroy(struct mk_http_thread *mth)
{
    struct mk_thread *th;

    /* Unlink from scheduler thread list */
    mk_list_del(&mth->_head);

    /* release original memory context */
    th = mth->parent;
    mth->session->channel->event->type = MK_EVENT_CONNECTION;
    mk_thread_destroy(th);

    return 0;
}

int mk_http_thread_event(struct mk_event *event)
{
    struct mk_sched_conn *conn = (struct mk_sched_conn *) event;

    /*
    struct mk_thread *th;
    struct mk_http_thread *mth;

    th = conn->channel.thread;
    mth = (struct mk_http_thread *) MK_THREAD_DATA(th);
    */

    mk_thread_resume(conn->channel.thread);
    return 0;
}

/*
 * Start the co-routine: invoke coroutine callback and start processing
 * data flush requests.
 */
int mk_http_thread_start(struct mk_http_thread *mth)
{
    mk_http_thread_resume(mth);
    return 0;
}
