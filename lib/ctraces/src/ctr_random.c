/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#include <ctraces/ctraces.h>

#if defined(unix) || defined (__unix) || defined(__unix__) || defined(__linux__) || \
    defined(__APPLE__) || defined(__MACH__) || defined(__FreeBSD__) || defined(__ANDROID__)
#define ITS_A_UNIX_FRIEND
#endif

#ifdef CTR_HAVE_GETRANDOM
#include <sys/random.h>
#endif

#ifdef ITS_A_UNIX_FRIEND
#include <fcntl.h>
#include <unistd.h>
#else
// #define needed to link in RtlGenRandom(), a.k.a. SystemFunction036.  See the
// "Community Additions" comment on MSDN here:
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa387694.aspx
#define SystemFunction036 NTAPI SystemFunction036
#include <ntsecapi.h>
#undef SystemFunction036

#endif

#include <time.h>

ssize_t ctr_random_get(void *buf, size_t len)
{
    int i;
    ssize_t ret = 0;
    unsigned int s;
    char *tmp;

#ifdef CTR_HAVE_GETRANDOM
    /*
     * On Linux systems getrandom() is preferred, note that our use case it's pretty
     * simple (no security stuff).
     */
    ret = getrandom(buf, len, GRND_NONBLOCK);
    return ret;
#endif

    /* if getrandom() is not available and we are on Linux, macOS or BSD, try out /dev/urandom */
#ifdef ITS_A_UNIX_FRIEND
    int fd;

    fd = open("/dev/urandom",  O_RDONLY);
    if (fd > 0) {
        ret = read(fd, buf, len);
        close(fd);
        return ret;
    }

    s = time(NULL);

    /* fallback... a very slow way to compose a random buffer */
    tmp = buf;
    for (i = 0; i < len; i++) {
        /* fixme: we need a good entropy here */
        tmp[i] = rand_r(&s);
    }
#else /* Windows ? */
    ret = RtlGenRandom(buf, len);
#endif

    return ret;
}
