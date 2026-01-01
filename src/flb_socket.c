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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_socket.h>

#ifndef _WIN32

int flb_socket_error(int fd)
{
    int ret;
    int error = 0;
    socklen_t slen = sizeof(error);

    ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &slen);
    if (ret == -1) {
        flb_debug("[socket] could not validate socket status for #%i (don't worry)",
                  fd);
        return -1;
    }

    if (error != 0) {
        return error;
    }

    return 0;
}

#endif
