/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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
                                   struct mk_http_request *sr,
                                   struct mk_http_session *cs)
{
    struct cgi_request *newcgi = mk_api->mem_alloc_z(sizeof(struct cgi_request));
    if (!newcgi) return NULL;

    newcgi->fd = fd;
    newcgi->socket = socket;
    newcgi->sr = sr;
    newcgi->cs = cs;

    return newcgi;
}

void cgi_req_add(struct cgi_request *r)
{
    struct mk_list *list = pthread_getspecific(cgi_request_list);
    mk_list_add(&r->_head, list);
}

int cgi_req_del(struct cgi_request *r)
{
    if (!r) return 1;

    mk_list_del(&r->_head);
    mk_api->mem_free(r);

    return 0;
}
