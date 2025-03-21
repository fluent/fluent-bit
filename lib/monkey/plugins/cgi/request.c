/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
 *  Copyright (C) 2012-2013, Lauri Kasanen
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

#include "cgi.h"

struct cgi_request *cgi_req_create(int fd, int socket,
                                   struct mk_plugin *plugin,
                                   struct mk_http_request *sr,
                                   struct mk_http_session *cs)
{
    struct cgi_request *cgi;

    cgi = mk_api->mem_alloc_z(sizeof(struct cgi_request));
    if (!cgi) {
        return NULL;
    }

    cgi->fd = fd;
    cgi->socket = socket;
    cgi->plugin = plugin;
    cgi->sr = sr;
    cgi->cs = cs;
    cgi->hangup = MK_TRUE;
    cgi->active = MK_TRUE;
    cgi->in_len = 0;

    cgi->event.mask   = MK_EVENT_EMPTY;
    cgi->event.status = MK_EVENT_NONE;

    return cgi;
}

void cgi_req_add(struct cgi_request *r)
{
    struct mk_list *list;

    list = pthread_getspecific(cgi_request_list);
    mk_list_add(&r->_head, list);
}

int cgi_req_del(struct cgi_request *r)
{
    PLUGIN_TRACE("Delete request child_fd=%i child_pid=%lu",
                 r->fd, r->child);

    mk_list_del(&r->_head);
    if (r->active == MK_FALSE) {
        mk_api->sched_event_free(&r->event);
    }
    else {
        mk_mem_free(r);
    }

    return 0;
}
