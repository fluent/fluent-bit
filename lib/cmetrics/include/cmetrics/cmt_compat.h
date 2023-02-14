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
