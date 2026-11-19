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

#include "cmetrics/lib/mpack/src/mpack/mpack.h"
#include <msgpack.h>
#include <mpack/mpack.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_strptime.h>
#include <fluent-bit/flb_time.h>
#include <stdint.h>
#ifdef FLB_HAVE_CLOCK_GET_TIME
#  include <mach/clock.h>
#  include <mach/mach.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#define ONESEC_IN_NSEC 1000000000

static int is_valid_format(int fmt)
{
    return (FLB_TIME_ETFMT_INT <= fmt) && (fmt < FLB_TIME_ETFMT_OTHER) ?
      FLB_TRUE : FLB_FALSE;
}

static int _flb_time_get(struct flb_time *tm)
{
    if (tm == NULL) {
        return -1;
    }
#if defined FLB_TIME_FORCE_FMT_INT
    tm->tm.tv_sec  = time(NULL);
    tm->tm.tv_nsec = 0;
    return 0;
#elif defined FLB_HAVE_TIMESPEC_GET
    /* C11 supported! */
    return timespec_get(&tm->tm, TIME_UTC);
#elif defined FLB_CLOCK_GET_TIME
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    tm->tv_sec = mts.tv_sec;
    tm->tv_nsec = mts.tv_nsec;
    return mach_port_deallocate(mach_task_self(), cclock);
#else /* __STDC_VERSION__ */
    return clock_gettime(CLOCK_REALTIME, &tm->tm);
#endif
}

int flb_time_get(struct flb_time *tm)
{
    return _flb_time_get(tm);
}

/* A portable function to sleep N msec */
int flb_time_msleep(uint32_t ms)
{
#ifdef _MSC_VER
    Sleep((DWORD) ms);
    return 0;
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    return nanosleep(&ts, NULL);
#endif
}

double flb_time_to_double(struct flb_time *tm)
{
    return (double)(tm->tm.tv_sec) + ((double)tm->tm.tv_nsec/(double)ONESEC_IN_NSEC);
}

uint64_t flb_time_to_nanosec(struct flb_time *tm)
{
    return (((uint64_t)tm->tm.tv_sec * 1000000000L) + tm->tm.tv_nsec);
}

uint64_t flb_time_to_millisec(struct flb_time *tm)
{
    return (((uint64_t)tm->tm.tv_sec * 1000L) + tm->tm.tv_nsec / 1000000L);
}

int flb_time_add(struct flb_time *base, struct flb_time *duration, struct flb_time *result)
{
    if (base == NULL || duration == NULL|| result == NULL) {
        return -1;
    }
    result->tm.tv_sec  = base->tm.tv_sec  + duration->tm.tv_sec;
    result->tm.tv_nsec = base->tm.tv_nsec + duration->tm.tv_nsec;

    if (result->tm.tv_nsec > ONESEC_IN_NSEC) {
        result->tm.tv_nsec -= ONESEC_IN_NSEC;
        result->tm.tv_sec++;
    } else if (result->tm.tv_nsec < 0) {
        result->tm.tv_nsec += ONESEC_IN_NSEC;
        result->tm.tv_sec--;
    }

    return 0;
}

int flb_time_diff(struct flb_time *time1,
                  struct flb_time *time0,struct flb_time *result)
{
    if (time1 == NULL || time0 == NULL || result == NULL) {
        return -1;
    }

    if (time1->tm.tv_sec >= time0->tm.tv_sec) {
        result->tm.tv_sec = time1->tm.tv_sec - time0->tm.tv_sec;
        if (time1->tm.tv_nsec >= time0->tm.tv_nsec) {
            result->tm.tv_nsec = time1->tm.tv_nsec - time0->tm.tv_nsec;
        }
        else if(result->tm.tv_sec == 0){
            /* underflow */
            return -2;
        }
        else{
            result->tm.tv_nsec = ONESEC_IN_NSEC
                               + time1->tm.tv_nsec - time0->tm.tv_nsec;
            result->tm.tv_sec--;
        }
    }
    else {
        /* underflow */
        return -3;
    }
    return 0;
}

int flb_time_append_to_mpack(mpack_writer_t *writer, struct flb_time *tm, int fmt)
{
    int ret = 0;
    struct flb_time l_time;
    char ext_data[8];
    uint32_t tmp;

    if (!is_valid_format(fmt)) {
#ifdef FLB_TIME_FORCE_FMT_INT
        fmt = FLB_TIME_ETFMT_INT;
#else
        fmt = FLB_TIME_ETFMT_V1_FIXEXT;
#endif
    }

    if (tm == NULL) {
      if (fmt == FLB_TIME_ETFMT_INT) {
         l_time.tm.tv_sec = time(NULL);
      }
      else {
        _flb_time_get(&l_time);
      }
      tm = &l_time;
    }

    switch(fmt) {
    case FLB_TIME_ETFMT_INT:
        mpack_write_uint(writer, tm->tm.tv_sec);
        break;

    case FLB_TIME_ETFMT_V0:
    case FLB_TIME_ETFMT_V1_EXT:
        /* We can't set with msgpack-c !! */
        /* see pack_template.h and msgpack_pack_inline_func(_ext) */
    case FLB_TIME_ETFMT_V1_FIXEXT:
        if (flb_time_is_valid_eventtime(tm) != FLB_TRUE) {
            return -1;
        }

        tmp = htonl((uint32_t)tm->tm.tv_sec); /* second from epoch */
        memcpy(&ext_data, &tmp, 4);
        tmp = htonl((uint32_t)tm->tm.tv_nsec);/* nanosecond */
        memcpy(&ext_data[4], &tmp, 4);

        /* https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1#eventtime-ext-format */
        mpack_write_ext(writer, 0 /*ext type=0 */, ext_data, sizeof(ext_data));
        break;

    default:
        ret = -1;
    }

    return ret;
}

int flb_time_append_to_msgpack(struct flb_time *tm, msgpack_packer *pk, int fmt)
{
    int ret = 0;
    struct flb_time l_time;
    char ext_data[8];
    uint32_t tmp;

    if (!is_valid_format(fmt)) {
#ifdef FLB_TIME_FORCE_FMT_INT
        fmt = FLB_TIME_ETFMT_INT;
#else
        fmt = FLB_TIME_ETFMT_V1_FIXEXT;
#endif
    }

    if (tm == NULL) {
      if (fmt == FLB_TIME_ETFMT_INT) {
         l_time.tm.tv_sec = time(NULL);
      }
      else {
        _flb_time_get(&l_time);
      }
      tm = &l_time;
    }

    switch(fmt) {
    case FLB_TIME_ETFMT_INT:
        msgpack_pack_uint64(pk, tm->tm.tv_sec);
        break;

    case FLB_TIME_ETFMT_V0:
    case FLB_TIME_ETFMT_V1_EXT:
        /* We can't set with msgpack-c !! */
        /* see pack_template.h and msgpack_pack_inline_func(_ext) */
    case FLB_TIME_ETFMT_V1_FIXEXT:
        if (flb_time_is_valid_eventtime(tm) != FLB_TRUE) {
            return -1;
        }

        tmp = htonl((uint32_t)tm->tm.tv_sec); /* second from epoch */
        memcpy(&ext_data, &tmp, 4);
        tmp = htonl((uint32_t)tm->tm.tv_nsec);/* nanosecond */
        memcpy(&ext_data[4], &tmp, 4);

        msgpack_pack_ext(pk, 8/*fixext8*/, 0);
        msgpack_pack_ext_body(pk, ext_data, sizeof(ext_data));

        break;

    default:
        ret = -1;
    }

    return ret;
}

static inline int is_eventtime(msgpack_object *obj)
{
    if (obj->via.ext.type != 0 || obj->via.ext.size != 8) {
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

int flb_time_msgpack_to_time(struct flb_time *time, msgpack_object *obj)
{
    uint32_t tmp;

    switch(obj->type) {
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        time->tm.tv_sec  = obj->via.u64;
        time->tm.tv_nsec = 0;
        break;
    case MSGPACK_OBJECT_FLOAT:
        time->tm.tv_sec  = obj->via.f64;
        time->tm.tv_nsec = ((obj->via.f64 - time->tm.tv_sec) * ONESEC_IN_NSEC);
        break;
    case MSGPACK_OBJECT_EXT:
        if (is_eventtime(obj) != FLB_TRUE) {
            flb_warn("[time] unknown ext type. type=%d size=%d",
                     obj->via.ext.type, obj->via.ext.size);
            return -1;
        }
        memcpy(&tmp, &obj->via.ext.ptr[0], 4);
        time->tm.tv_sec = (uint32_t) ntohl(tmp);
        memcpy(&tmp, &obj->via.ext.ptr[4], 4);
        time->tm.tv_nsec = (uint32_t) ntohl(tmp);
        if (flb_time_is_valid_eventtime(time) != FLB_TRUE) {
            flb_warn("[time] invalid EventTime value");
            return -1;
        }
        break;
    default:
        flb_warn("unknown time format %x", obj->type);
        return -1;
    }

    return 0;
}

/*
 * Parse the fractional seconds matched by the '%L' specifier:
 *
 *   2020-10-23T12:00:31.415213Z
 *                      ------
 *
 * Returns the number of characters consumed or -1 on error.
 */
static int parse_subseconds(const char *str, size_t len, double *subsec)
{
    int digits = 9;  /* 1 ns = 000000001 (9 digits) */
    int consumed;
    char *end;
    char buf[16];

    if (len < (size_t) digits) {
        digits = (int) len;
    }

    memcpy(buf, "0.", 2);
    memcpy(buf + 2, str, digits);
    buf[digits + 2] = '\0';

    *subsec = strtod(buf, &end);

    consumed = end - buf - 2;
    if (consumed <= 0) {
        return -1;
    }

    return consumed;
}

int flb_time_fmt_create(struct flb_time_fmt *tf, const char *format)
{
    char *frac;

    if (tf == NULL || format == NULL) {
        return -1;
    }

    tf->frac_secs = NULL;
    tf->fmt = flb_strdup(format);
    if (tf->fmt == NULL) {
        flb_errno();
        return -1;
    }

    frac = strstr(tf->fmt, "%L");
    if (frac != NULL) {
        *frac = '\0';
        tf->frac_secs = frac + 2;
    }

    return 0;
}

void flb_time_fmt_destroy(struct flb_time_fmt *tf)
{
    if (tf == NULL) {
        return;
    }

    if (tf->fmt != NULL) {
        flb_free(tf->fmt);
        tf->fmt = NULL;
    }

    tf->frac_secs = NULL;
}

/*
 * Convert a timestamp string into 'tm'. When 'tf' holds a prepared format the
 * value is parsed with strptime(3) semantics, otherwise the value is expected
 * to contain a numeric Unix timestamp.
 *
 * The whole value must be consumed, a partial match is not considered a valid
 * timestamp.
 */
int flb_time_from_str(struct flb_time *tm, const char *str, size_t len,
                      struct flb_time_fmt *tf)
{
    int consumed;
    char *end;
    char *p;
    char buf[FLB_TIME_STR_MAX];
    long int gmtoff;
    double subsec = 0.0;
    double value;
    struct tm tm_conv;
    struct flb_tm tmp;
    struct flb_tm frac_tmp;

    if (tm == NULL || str == NULL || len == 0 || len >= sizeof(buf)) {
        return -1;
    }

    /* both flb_strptime(3) and strtod(3) require a null terminated string */
    memcpy(buf, str, len);
    buf[len] = '\0';

    if (tf == NULL || tf->fmt == NULL) {
        errno = 0;
        value = strtod(buf, &end);

        /*
         * non finite values are rejected: they cannot be represented as a
         * timestamp and they serialize to invalid JSON.
         */
        if (end == buf || errno == ERANGE || !isfinite(value)) {
            return -1;
        }

        while (isspace((unsigned char) *end)) {
            end++;
        }

        if (*end != '\0') {
            return -1;
        }

        tm->tm.tv_sec = (time_t) value;
        tm->tm.tv_nsec = (long) ((value - (double) tm->tm.tv_sec) *
                                 ONESEC_IN_NSEC);

        return 0;
    }

    memset(&tmp, 0, sizeof(struct flb_tm));

    p = flb_strptime(buf, tf->fmt, &tmp);
    if (p == NULL) {
        return -1;
    }

    if (tf->frac_secs != NULL) {
        consumed = parse_subseconds(p, len - (p - buf), &subsec);
        if (consumed < 0) {
            return -1;
        }
        p += consumed;

        /*
         * flb_strptime() resets the timezone offset on every call, so the part
         * of the format that follows '%L' is parsed into a separate structure
         * and only a timezone that it actually matched is carried over.
         */
        memset(&frac_tmp, 0, sizeof(struct flb_tm));

        p = flb_strptime(p, tf->frac_secs, &frac_tmp);
        if (p == NULL) {
            return -1;
        }

        if (flb_tm_gmtoff(&frac_tmp) != 0) {
            flb_tm_gmtoff(&tmp) = flb_tm_gmtoff(&frac_tmp);
        }
    }

    while (isspace((unsigned char) *p)) {
        p++;
    }

    if (*p != '\0') {
        return -1;
    }

    /*
     * timegm(3) normalizes the structure it receives, and on platforms where
     * the timezone offset is a member of 'struct tm' it is reset by the
     * conversion, so the offset is saved and a copy is handed over.
     */
    gmtoff = flb_tm_gmtoff(&tmp);
    tm_conv = tmp.tm;

    flb_time_set(tm, timegm(&tm_conv) - gmtoff,
                 (long) (subsec * ONESEC_IN_NSEC));

    return 0;
}

/*
 * Extract a timestamp out of a record value. This extends
 * flb_time_msgpack_to_time() with support for string values, which are parsed
 * using 'tf', and it rejects non finite floats.
 */
int flb_time_from_msgpack_object(struct flb_time *tm, msgpack_object *obj,
                                 struct flb_time_fmt *tf)
{
    if (tm == NULL || obj == NULL) {
        return -1;
    }

    switch (obj->type) {
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        flb_time_set(tm, (time_t) obj->via.u64, 0);
        break;
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        flb_time_set(tm, (time_t) obj->via.i64, 0);
        break;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        if (!isfinite(obj->via.f64)) {
            return -1;
        }
        tm->tm.tv_sec = (time_t) obj->via.f64;
        tm->tm.tv_nsec = (long) ((obj->via.f64 - (double) tm->tm.tv_sec) *
                                 ONESEC_IN_NSEC);
        break;
    case MSGPACK_OBJECT_STR:
        return flb_time_from_str(tm, obj->via.str.ptr, obj->via.str.size, tf);
    case MSGPACK_OBJECT_EXT:
        return flb_time_msgpack_to_time(tm, obj);
    default:
        return -1;
    }

    return 0;
}

int flb_time_pop_from_mpack(struct flb_time *time, mpack_reader_t *reader)
{
    mpack_tag_t tag;
    double d;
    float f;
    int64_t i;
    uint32_t tmp;
    char extbuf[8];
    size_t ext_len;
    int header_detected;

    if (time == NULL) {
        return -1;
    }

    header_detected = FLB_FALSE;

    /* consume the record array */
    tag = mpack_read_tag(reader);

    if (mpack_reader_error(reader) != mpack_ok ||
        mpack_tag_type(&tag) != mpack_type_array ||
        mpack_tag_array_count(&tag) == 0) {
        return -1;
    }

    /* consume the header array or the timestamp
     * depending on the chunk encoding
     */
    tag = mpack_read_tag(reader);

    if (mpack_reader_error(reader) != mpack_ok) {
        return -1;
    }

    if (mpack_tag_type(&tag) == mpack_type_array) {
        if(mpack_tag_array_count(&tag) != 2) {
            return -1;
        }

        /* consume the timestamp element */
        tag = mpack_read_tag(reader);

        if (mpack_reader_error(reader) != mpack_ok) {
            return -1;
        }

        header_detected = FLB_TRUE;
    }

    switch (mpack_tag_type(&tag)) {
        case mpack_type_int:
            i = mpack_tag_int_value(&tag);
            if (i < 0) {
                flb_warn("expecting positive integer, got %" PRId64, i);
                return -1;
            }
            time->tm.tv_sec  = i;
            time->tm.tv_nsec = 0;
            break;
        case mpack_type_uint:
            time->tm.tv_sec  = mpack_tag_uint_value(&tag);
            time->tm.tv_nsec = 0;
            break;
        case mpack_type_float:
            f = mpack_tag_float_value(&tag);
            time->tm.tv_sec = f;
            time->tm.tv_nsec = ((f - time->tm.tv_sec) * ONESEC_IN_NSEC);
        case mpack_type_double:
            d = mpack_tag_double_value(&tag);
            time->tm.tv_sec  = d;
            time->tm.tv_nsec = ((d - time->tm.tv_sec) * ONESEC_IN_NSEC);
            break;
        case mpack_type_ext:
            ext_len = mpack_tag_ext_length(&tag);
            if (ext_len != 8) {
                flb_warn("expecting ext_len is 8, got %ld", ext_len);
                return -1;
            }
            mpack_read_bytes(reader, extbuf, ext_len);
            memcpy(&tmp, extbuf, 4);
            time->tm.tv_sec = (uint32_t) ntohl(tmp);
            memcpy(&tmp, extbuf + 4, 4);
            time->tm.tv_nsec = (uint32_t) ntohl(tmp);
            if (flb_time_is_valid_eventtime(time) != FLB_TRUE) {
                flb_warn("invalid EventTime value");
                return -1;
            }
            break;
        default:
            flb_warn("unknown time format %d", tag.type);
            return -1;
    }

    /* discard the metadata map if present */

    if (header_detected) {
        mpack_discard(reader);
    }

    return 0;
}

int flb_time_pop_from_msgpack(struct flb_time *time, msgpack_unpacked *upk,
                              msgpack_object **map)
{
    int ret;
    msgpack_object obj;

    if (time == NULL || upk == NULL) {
        return -1;
    }

    if (upk->data.type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    obj = upk->data.via.array.ptr[0];

    if (obj.type == MSGPACK_OBJECT_ARRAY) {
        if (obj.via.array.size != 2) {
            return -1;
        }

        obj = obj.via.array.ptr[0];
    }

    *map = &upk->data.via.array.ptr[1];

    ret = flb_time_msgpack_to_time(time, &obj);
    return ret;
}

long flb_time_tz_offset_to_second()
{
    time_t t = time(NULL);
    struct tm local = *localtime(&t);
    struct tm utc = *gmtime(&t);

    long diff = ((local.tm_hour - utc.tm_hour)          \
                 * 60 + (local.tm_min - utc.tm_min))    \
                 * 60L + (local.tm_sec - utc.tm_sec);

    int delta_day = local.tm_mday - utc.tm_mday;

    if ((delta_day == 1) || (delta_day < -1)) {
        diff += 24L * 60 * 60;
    }
    else if ((delta_day == -1) || (delta_day > 1)) {
        diff -= 24L * 60 * 60;
    }

    return diff;
}

#include "flb_time_tz.c"
