/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_IO_H
#define FLB_IO_H

#include <stddef.h>
#include <monkey/mk_core.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_coro.h>

/* Coroutine status 'flb_coro.status' */
#define FLB_IO_CONNECT     0  /* thread issue a connection request */
#define FLB_IO_WRITE       1  /* thread wants to write() data      */

/* Network operation modes */
#define FLB_IO_TCP         1  /* use plain TCP                          */
#define FLB_IO_TLS         2  /* use TLS/SSL layer                      */
#define FLB_IO_OPT_TLS     4  /* use TCP and optional TLS               */
#define FLB_IO_ASYNC       8  /* use async mode (depends on event loop) */
#define FLB_IO_TCP_KA     16  /* use async mode (depends on event loop) */

/* Other features */
#define FLB_IO_IPV6       32  /* network I/O uses IPv6                  */

struct flb_connection;
struct flb_iovec {
    void   *iov_base;
    size_t  iov_len;
};

int flb_io_net_accept(struct flb_connection *connection,
                       struct flb_coro *th);

int flb_io_net_connect(struct flb_connection *u_conn,
                       struct flb_coro *th);

int flb_io_net_write(struct flb_connection *connection, const void *data,
                     size_t len, size_t *out_len);

int flb_io_net_writev(struct flb_connection *connection,
                      const struct flb_iovec *iov,
                      int iovcnt,
                      size_t *out_len);

ssize_t flb_io_net_read(struct flb_connection *connection, void *buf, size_t len);

int flb_io_fd_write(int fd, const void *data, size_t len, size_t *out_len);

ssize_t flb_io_fd_read(int fd, void *buf, size_t len);

#endif
