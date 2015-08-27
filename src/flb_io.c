/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

/*
 * FLB_IO
 * ======
 * This interface is used by the output plugins which needs to write over
 * the network in plain communication or through the TLS support. When dealing
 * with network operation there are a few things to keep in mind:
 *
 * - TCP hosts can be down.
 * - Network can be slow.
 * - If the amount of data to flush requires multiple 'write' operations, we
 *   should not block the main thread, instead use event-driven mechanism to
 *   write when is possible.
 *
 * Output plugins that flag their selfs with FLB_OUTPUT_TCP or FLB_OUTPUT_TLS
 * can take advante of this interface.
 *
 * The workflow to use this is the following:
 *
 * - A connection and data flow requires an flb_io_upstream context.
 * - We write data through the flb_io_write() interface.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>

/* Creates a new upstream context */
struct flb_io_upstream *flb_io_upstream_new(char *host, int port, int flags)
{
    int fd;
    struct flb_io_upstream *u;

    u = malloc(sizeof(struct flb_io_upstream));
    if (!u) {
        perror("malloc");
        return NULL;
    }


    /* Upon upstream creation, we always try to perform a connection */
    flb_debug("[upstream] connecting to %s:%i", host, port);
    fd = flb_net_tcp_connect(host, port);
    if (fd == -1) {
        flb_warn("[upstream] could not connect to %s:%i", host, port);
    }
    else {
        flb_debug("[upstream] connected!");
    }

    u->fd   = fd;
    u->tcp_host = strdup(host);
    u->tcp_port = port;
    u->flags    = flags;

    return u;
}

/* Write data to an upstream connection/server */
int flb_io_write(struct flb_io_upstream *u, void *data, size_t len, size_t *out_len)
{
    int bytes;

    bytes = write(u->fd, data, len);
    *out_len = bytes;
    return bytes;
}
