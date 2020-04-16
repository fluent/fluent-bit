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

#ifndef FLB_TIME_H
#define FLB_TIME_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_time_utils.h>

#include <time.h>
#include <msgpack.h>
struct flb_time {
    struct timespec tm;
};

/*
   to represent eventtime of fluentd
   see also
   https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v0#eventtime-ext-format
   https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1#eventtime-ext-format
 */
enum flb_time_eventtime_fmt {
    FLB_TIME_ETFMT_INT = 1,   /* second(integer) only */
    FLB_TIME_ETFMT_V0,        /* EventTime (v0) */
    FLB_TIME_ETFMT_V1_EXT,    /* EventTime (v1 ext) */
    FLB_TIME_ETFMT_V1_FIXEXT, /* EventTime (v1 fixext) */
    FLB_TIME_ETFMT_OTHER,
};

static inline void flb_time_zero(struct flb_time *tm)
{
    tm->tm.tv_sec = 0;
    tm->tm.tv_nsec = 0;
}

static inline void flb_time_set(struct flb_time *tm, time_t sec, long nsec)
{
    tm->tm.tv_sec = sec;
    tm->tm.tv_nsec = nsec;
}

static inline void flb_time_copy(struct flb_time *dst, struct flb_time *src)
{
    dst->tm.tv_sec = src->tm.tv_sec;
    dst->tm.tv_nsec = src->tm.tv_nsec;
}

static inline void flb_time_from_double(struct flb_time *dst, double d)
{
    dst->tm.tv_sec = (int) d;
    dst->tm.tv_nsec = (long) ((d - dst->tm.tv_sec) * 1000000000L);
}

static inline int flb_time_equal(struct flb_time *t0, struct flb_time *t1) {
    return t0->tm.tv_sec == t1->tm.tv_sec && t0->tm.tv_nsec == t1->tm.tv_nsec;
}

int flb_time_get(struct flb_time *tm);
int flb_time_msleep(uint32_t ms);
double flb_time_to_double(struct flb_time *tm);
int flb_time_add(struct flb_time *base, struct flb_time *duration,
                 struct flb_time *result);
int flb_time_diff(struct flb_time *time1,
                  struct flb_time *time0, struct flb_time *result);
int flb_time_append_to_msgpack(struct flb_time *tm, msgpack_packer *pk, int fmt);
int flb_time_pop_from_msgpack(struct flb_time *time, msgpack_unpacked *upk,
                              msgpack_object **map);

#endif /* FLB_TIME_H */
