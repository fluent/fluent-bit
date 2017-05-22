/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "syslog.h"

int syslog_unix_create(struct flb_syslog *ctx)
{
    flb_sockfd_t fd;
    unsigned long len;
    size_t address_length;
    struct sockaddr_un address;

    umask(0);

    /* Create listening socket */
    fd = flb_net_socket_create(PF_UNIX, FLB_FALSE);
    if (fd == -1) {
      return -1;
    }

    if (fchmod(fd, ctx->mode) != 0) {
        flb_errno();
        close(fd);
        return -1;
    }

    unlink(ctx->unix_path);
    len = strlen(ctx->unix_path);

    address.sun_family = AF_UNIX;
    sprintf(address.sun_path, "%s", ctx->unix_path);
    address_length = sizeof(address.sun_family) + len + 1;
    if (bind(fd, (struct sockaddr *) &address, address_length) != 0) {
        flb_errno();
        close(fd);
        return -1;
    }

    if (listen(fd, 5) != 0) {
        flb_errno();
        close(fd);
        return -1;
    }

    flb_net_socket_nonblocking(fd);
    ctx->server_fd = fd;

    return fd;
}

int syslog_unix_destroy(struct flb_syslog *ctx)
{
    unlink(ctx->unix_path);
    flb_free(ctx->unix_path);
    close(ctx->server_fd);

    return 0;
}
