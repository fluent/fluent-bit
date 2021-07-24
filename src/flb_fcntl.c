/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_fcntl.h>
#include <fluent-bit/flb_log.h>

int flb_fcntl_cloexec(int fd)
{
#ifdef FD_CLOEXEC
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1) {
        flb_errno();
        return -1;
    }

    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
        flb_errno();
        return -1;
    }
#endif
    return 0;
}

int flb_open(const char *pathname, int flags, mode_t mode)
{
#ifdef O_CLOEXEC
    return open(pathname, flags | O_CLOEXEC, mode);
#else
    int fd = open(pathname, flags, mode);
    if (fd == -1) {
        return -1;
    }
    flb_fcntl_cloexec(fd);
    return fd;
#endif
}
