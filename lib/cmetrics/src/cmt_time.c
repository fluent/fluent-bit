/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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

#include <cmetrics/cmt_info.h>

/* MacOS */
#ifdef CMT_HAVE_CLOCK_GET_TIME
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#include <inttypes.h>
#include <time.h>

uint64_t cmt_time_now()
{
    struct timespec tm = {0};

#if defined CMT_HAVE_TIMESPEC_GET
    /* C11 supported */
    timespec_get(&tm, TIME_UTC);
#elif defined CMT_HAVE_CLOCK_GET_TIME
    /* MacOS */
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    tm.tv_sec = mts.tv_sec;
    tm.tv_nsec = mts.tv_nsec;
    mach_port_deallocate(mach_task_self(), cclock);
#else /* __STDC_VERSION__ */
    clock_gettime(CLOCK_REALTIME, &tm);
#endif

    return (((uint64_t) tm.tv_sec * 1000000000L) + tm.tv_nsec);
}

void cmt_time_from_ns(struct timespec *tm, uint64_t ns)
{
    if (ns < 1000000000L) {
        tm->tv_sec = 0;
        tm->tv_nsec = ns;
    }
    else {
        tm->tv_sec = ns / 1000000000L;
        tm->tv_nsec = ns - (tm->tv_sec * 1000000000L);
    }
}
