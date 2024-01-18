/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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


#include <fluent-bit/flb_pal.h>

#include <errno.h>
#include <string.h>

/*
 * The pal component encapsulates the platform dependency of the common
 * platform features used by the rest of the Fluent Bit implementation.
 */

/*
 * The wrapper of strerror_r(3).
 *
 * The signature follows that of POSIX.1-2001.
 *
 * Under glibc, copy the returned string to buf if the returned pointer is not
 * equal to buf.
 */
#if defined(FLB_HAVE_STRERROR_R) || defined(FLB_HAVE_STRERROR_S)
int flb_strerror_r(int errnum, char *buf, size_t buflen)
{
#if defined(FLB_HAVE_STRERROR_R)
#if defined(FLB_HAVE_STRERROR_R_CHAR_P)
    int ret;
    char *p;

    ret = 0;

    p = strerror_r(errnum, buf, buflen);
    if (NULL == p) {
        return errno;
    }
    if (p != buf) {
        if (strlen(p) > buflen - 1) {
            ret = ERANGE;
        }
        strncpy(buf, p, buflen - 1);
        buf[buflen - 1] = '\0';
    }

    return ret;
#else
    return strerror_r(errnum, buf, buflen);
#endif
#elif defined(FLB_HAVE_STRERROR_S)
    return (int) strerror_s(buf, (rsize_t)buflen, (errno_t)errnum);
#endif
}
#endif
