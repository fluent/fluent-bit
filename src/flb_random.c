/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_compat.h>
#include <fcntl.h>

/*
 * This module provides a random number generator for common use cases.
 *
 * On Windows, we use BCryptGenRandom() from CNG API. This function
 * is available since Windows Vista, and should be compliant to the
 * official recommendation.
 *
 * On Unix, we use /dev/urandom as a secure random source.
 */

int flb_random_bytes(unsigned char *buf, int len)
{
#ifdef FLB_SYSTEM_WINDOWS
    NTSTATUS ret;
    ret = BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(ret)) {
        return -1;
    }
    return 0;
#else
    int fd;
    int bytes;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    while (len > 0) {
        bytes = read(fd, buf, len);
        if (bytes <= 0) {
            close(fd);
            return -1;
        }
        len -= bytes;
        buf += bytes;
    }
    close(fd);
    return 0;
#endif
}
