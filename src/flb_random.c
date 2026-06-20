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

#include <fluent-bit/flb_compat.h>
#include <fcntl.h>

#ifdef FLB_HAVE_GETENTROPY
#include <unistd.h>
#endif
#ifdef FLB_HAVE_GETENTROPY_SYS_RANDOM
#include <sys/random.h>
#endif

#define MAX_GETENTROPY_LEN 256

/*
 * This module provides a random number generator for common use cases.
 *
 * On Windows, we use BCryptGenRandom() from CNG API. This function
 * is available since Windows Vista, and should be compliant to the
 * official recommendation.
 *
 * On other platforms, we use getentropy(3) if available, otherwise
 * /dev/urandom as a secure random source.
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
    int     fd;
    ssize_t bytes;

#if defined(FLB_HAVE_GETENTROPY) || defined(FLB_HAVE_GETENTROPY_SYS_RANDOM)
    while (len > 0) {
        if (len > MAX_GETENTROPY_LEN) {
            bytes = MAX_GETENTROPY_LEN;
        }
        else {
            bytes = len;
        }
        if (getentropy(buf, bytes) < 0) {
#ifdef ENOSYS
            /* Fall back to urandom if the syscall is not available (Linux only) */
            if (errno == ENOSYS) {                
                goto try_urandom;
            }
#endif
            return -1;
        }
        len -= bytes;
        buf += bytes;
    }
    return 0;

try_urandom:
#endif /* FLB_HAVE_GETENTROPY || FLB_HAVE_GETENTROPY_SYS_RANDOM */
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
#endif /* FLB_SYSTEM_WINDOWS */
}
