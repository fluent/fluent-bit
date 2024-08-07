/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#ifndef CMT_COMPAT_H
#define CMT_COMPAT_H

#include <time.h>
#ifdef _WIN32
#include <windows.h>
#endif

/* This function is copied from monkey/monkey.
   https://github.com/monkey/monkey/blob/2567a70912ed7a68d9e75dca3cf22d3927fea99a/mk_core/deps/libevent/evdns.c#L3323 */
static inline char *
cmt_platform_strtok_r(char *s, const char *delim, char **state) {
    char *cp, *start;
    start = cp = s ? s : *state;
    if (!cp)
        return NULL;
    while (*cp && !strchr(delim, *cp))
        ++cp;
    if (!*cp) {
        if (cp == start)
            return NULL;
        *state = NULL;
        return start;
    } else {
        *cp++ = '\0';
        *state = cp;
        return start;
    }
}

static inline struct tm *cmt_platform_gmtime_r(const time_t *timep, struct tm *result)
{
#ifdef CMT_HAVE_GMTIME_S
    if (gmtime_s(result, timep)) {
        return NULL;
    }

    return result;
#else
    /* FIXME: Need to handle gmtime_r(3) lacking platform? */
    return gmtime_r(timep, result) ;
#endif
}

#endif
