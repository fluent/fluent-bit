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

#ifndef MK_SERVER_H
#define MK_SERVER_H

#define _GNU_SOURCE
#include <monkey/mk_socket.h>
#include <monkey/mk_config.h>
#include <monkey/mk_core.h>

#define MK_SERVER_SIGNAL_START     0xEEEEEEEE
#define MK_SERVER_SIGNAL_STOP      0xDDDDDDDD

struct mk_server_listen
{
    struct mk_event event;

    int server_fd;
    struct mk_plugin *network;
    struct mk_sched_handler *protocol;
    struct mk_config_listener *listen;
    struct mk_list _head;
};

struct mk_server_timeout {
    struct mk_event event;
};

extern pthread_key_t mk_server_fifo_key;

#ifdef MK_HAVE_C_TLS
extern __thread struct mk_list *server_listen;
extern __thread struct mk_server_timeout *server_timeout;
#endif

struct mk_sched_worker;

int mk_socket_set_cork_flag(int fd, int state);

static inline int mk_server_cork_flag(int fd, int state)
{
    return mk_socket_set_cork_flag(fd, state);
}

struct mk_server *mk_server_create();
int mk_server_listen_check(struct mk_server_listen *listen, int server_fd);

void mk_server_listen_free();
struct mk_list *mk_server_listen_init(struct mk_server *server);

unsigned int mk_server_capacity(struct mk_server *server);
void mk_server_launch_workers(struct mk_server *server);
void mk_server_worker_loop(struct mk_server *server);
void mk_server_loop_balancer();
void mk_server_worker_loop();
void mk_server_loop(struct mk_server *server);

#endif
