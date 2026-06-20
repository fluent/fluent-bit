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

#ifndef FLB_SOCKET_H
#define FLB_SOCKET_H

#include <fluent-bit/flb_compat.h>

#ifdef _WIN32
#include <event.h>

#define flb_sockfd_t         evutil_socket_t

#define flb_socket_close(fd) evutil_closesocket(fd)
#define flb_socket_error(fd) evutil_socket_geterror(fd)

#define FLB_EINPROGRESS(e)   ((e) == WSAEWOULDBLOCK)
#define FLB_WOULDBLOCK()     (WSAGetLastError() == WSAEWOULDBLOCK)

#define FLB_INVALID_SOCKET   ((flb_sockfd_t) -1)
#else
#include <sys/types.h>
#include <sys/socket.h>

#define flb_sockfd_t         int

#define flb_socket_close(fd) close(fd)

#define FLB_EINPROGRESS(e)   ((e) == EINTR || (e) == EINPROGRESS)
#define FLB_WOULDBLOCK()     (errno == EAGAIN || errno == EWOULDBLOCK)

#define FLB_INVALID_SOCKET   ((flb_sockfd_t) -1)

int flb_socket_error(int fd);

#endif

#endif
