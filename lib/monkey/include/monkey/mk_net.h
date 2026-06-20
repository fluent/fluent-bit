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

#ifndef MK_NET_H
#define MK_NET_H

#include <monkey/mk_core.h>
#include <monkey/mk_stream.h>

struct mk_net_connection {
    struct mk_event event;
    int fd;
    char *host;
    int port;
    void *thread;
};

int mk_net_init();

struct mk_net_connection *mk_net_conn_create(char *addr, int port);
int mk_net_conn_write(struct mk_channel *channel,
                      void *data, size_t len);

#endif
