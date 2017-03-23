/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <msgpack.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>

#include <arpa/inet.h>
#include <string.h>

#define ONESEC_IN_NSEC 1000000000

static int is_valid_format(int fmt)
{
    return (FLB_TIME_ETFMT_INT <= fmt) && (fmt < FLB_TIME_ETFMT_OTHER) ?
      FLB_TRUE : FLB_FALSE;
}

static int _flb_time_get(flb_time *tm)
{
#if __STDC_VERSION__ >= 201112L
    /* C11 supported! */
    return timespec_get(tm, TIME_UTC);
#else /* __STDC_VERSION__ */
    return clock_gettime(CLOCK_REALTIME, tm);
#endif
}

int flb_time_diff(flb_time *time1, flb_time *time0, flb_time *result)
{
    if (time1 == NULL || time0 == NULL || result == NULL) {
        return -1;
    }
    
    if (time1->tv_sec >= time0->tv_sec) {
        result->tv_sec = time1->tv_sec - time0->tv_sec;
        if (time1->tv_nsec >= time0->tv_nsec) {
            result->tv_nsec = time1->tv_nsec - time0->tv_nsec;
        }
        else if(result->tv_sec == 0){
            /* underflow */
            return -1;
        }
        else{
            result->tv_nsec = ONESEC_IN_NSEC - time1->tv_nsec - time0->tv_nsec;
            result->tv_sec--;
        }
    }
    else {
        /* underflow */
        return -1;
    }
    return 0;
}


int flb_time_append_to_msgpack(flb_time *tm, msgpack_packer *pk, int fmt)
{
    int ret = 0;
    flb_time l_time;
    char ext_data[8];
    int32_t tmp;

    if (!is_valid_format(fmt)) {
        fmt = FLB_TIME_ETFMT_INT;
    }

    if (tm == NULL) {
      if (fmt == FLB_TIME_ETFMT_INT) {
         l_time.tv_sec = time(NULL);
      }
      else {
        _flb_time_get(&l_time);
      }
      tm = &l_time;
    }

    switch(fmt) {
    case FLB_TIME_ETFMT_INT:
        msgpack_pack_uint64(pk, tm->tv_sec);
        break;

    case FLB_TIME_ETFMT_V0:
    case FLB_TIME_ETFMT_V1_EXT:
        /* We can't set with msgpack-c !! */
        /* see pack_template.h and msgpack_pack_inline_func(_ext) */
    case FLB_TIME_ETFMT_V1_FIXEXT:
        tmp = htonl((int32_t)tm->tv_sec); /* second from epoch */
        memcpy(&ext_data, &tmp, 4);
        tmp = htonl((int32_t)tm->tv_nsec);/* nanosecond */
        memcpy(&ext_data[4], &tmp, 4);

        msgpack_pack_ext(pk, 8/*fixext8*/, 0);
        msgpack_pack_ext_body(pk, ext_data, sizeof(ext_data));
        break;

    default:
        ret = -1;
    }

    return ret;
}

int flb_time_pop_from_msgpack(flb_time *time, msgpack_unpacked *upk, int *fmt,
                              msgpack_object **map)
{
    msgpack_object obj;

    if(time == NULL || upk == NULL) {
        return -1;
    }
    obj = upk->data.via.array.ptr[0];

    switch(obj.type){
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        if (fmt != NULL) {
          *fmt = FLB_TIME_ETFMT_INT;
        }
        time->tv_sec  = obj.via.u64;
        time->tv_nsec = 0;
        break;

    case MSGPACK_OBJECT_EXT:
        /* TBD */
        break;
    default:
        flb_warn("unknown time format");
        return -1;
    }

    *map = &upk->data.via.array.ptr[1];
    return 0;
}
