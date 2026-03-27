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

/*
 * This is a dumb implementation of langinfo.h that only supports LC_TIME
 * and "C" locale. We use this implemenatation to support locale-dependent
 * specifiers of strptime(3) on Windows.
 */

#ifndef FLB_LANGINFO_H
#define FLB_LANGINFO_H

/*
 * ucrt on Windows does not have nl_langinfo at all.
 * bionic libc on Android does not provide this methoid prior to Android O / API Level 26 according to
 * https://android.googlesource.com/platform/bionic/+/master/docs/status.md
 */
#if defined(_MSC_VER) || (defined(__ANDROID__) && __ANDROID_API < 26)

typedef int nl_item;

#define D_T_FMT  0x00
#define D_FMT    0x01
#define T_FMT    0x02

#define DAY_1    0x03
#define DAY_2    0x04
#define DAY_3    0x05
#define DAY_4    0x06
#define DAY_5    0x07
#define DAY_6    0x08
#define DAY_7    0x09

#define ABDAY_1  0x0A
#define ABDAY_2  0x0B
#define ABDAY_3  0x0C
#define ABDAY_4  0x0D
#define ABDAY_5  0x0E
#define ABDAY_6  0x0F
#define ABDAY_7  0x10

#define MON_1    0x11
#define MON_2    0x12
#define MON_3    0x13
#define MON_4    0x14
#define MON_5    0x15
#define MON_6    0x16
#define MON_7    0x17
#define MON_8    0x18
#define MON_9    0x19
#define MON_10   0x1A
#define MON_11   0x1B
#define MON_12   0x1C

#define ABMON_1  0x1D
#define ABMON_2  0x1E
#define ABMON_3  0x1F
#define ABMON_4  0x20
#define ABMON_5  0x21
#define ABMON_6  0x22
#define ABMON_7  0x23
#define ABMON_8  0x24
#define ABMON_9  0x25
#define ABMON_10 0x26
#define ABMON_11 0x27
#define ABMON_12 0x28

#define AM_STR     0x29
#define PM_STR     0x2A
#define T_FMT_AMPM 0x2B

static const char *lc_time_c[] = {
    "%a %b %e %H:%M:%S %Y", /* D_T_FMT */
    "%m/%d/%y",    /* D_FMT */
    "%H:%M:%S",    /* T_FMT */

    "Sunday",      /* DAY_1 */
    "Monday",      /* DAY_2 */
    "Tuesday",     /* DAY_3 */
    "Wednesday",   /* DAY_4 */
    "Thursday",    /* DAY_5 */
    "Friday",      /* DAY_6 */
    "Saturday",    /* DAY_7 */

    "Sun",         /* ABDAY_1 */
    "Mon",         /* ABDAY_2 */
    "Tue",         /* ABDAY_3 */
    "Wed",         /* ABDAY_4 */
    "Thu",         /* ABDAY_5 */
    "Fri",         /* ABDAY_6 */
    "Sat",         /* ABDAY_7 */

    "January",     /* MON_1 */
    "February",    /* MON_2 */
    "March",       /* MON_3 */
    "April",       /* MON_4 */
    "May",         /* MON_5 */
    "June",        /* MON_6 */
    "July",        /* MON_7 */
    "August",      /* MON_8 */
    "September",   /* MON_9 */
    "October",     /* MON_10 */
    "November",    /* MON_11 */
    "December",    /* MON_12 */

    "Jan",         /* ABMON_1 */
    "Feb",         /* ABMON_2 */
    "Mar",         /* ABMON_3 */
    "Apr",         /* ABMON_4 */
    "May",         /* ABMON_5 */
    "Jun",         /* ABMON_6 */
    "Jul",         /* ABMON_7 */
    "Aug",         /* ABMON_8 */
    "Sep",         /* ABMON_9 */
    "Oct",         /* ABMON_10 */
    "Nov",         /* ABMON_11 */
    "Dec",         /* ABMON_12 */

    "AM",          /* AM_STR */
    "PM",          /* PM_STR */
    "%I:%M:%S %p", /* T_FMT_AMPM */
};

static inline const char *nl_langinfo(nl_item item)
{
    if (item < 0 || 0x2B < item)
        return "";
    return lc_time_c[item];
}
#else
#include <langinfo.h>
#endif
#endif
