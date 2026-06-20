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

#ifndef FLB_BYTESWAP_H
#define FLB_BYTESWAP_H

#include <stdint.h>
#include <fluent-bit/flb_endian.h>

#if defined(FLB_HAVE_WIN32_BYTESWAP)
#include <stdlib.h>
#elif defined(FLB_HAVE_CLANG_BYTESWAP)
#include <intrin.h>
#elif defined(FLB_HAVE_POSIX_BYTESWAP)
#include <byteswap.h>
#endif

#if defined(FLB_HAVE_WIN32_BYTESWAP) || \
    defined(FLB_HAVE_CLANG_BYTESWAP)
#define FLB_BSWAP_16(value) _byteswap_ushort(value)
#define FLB_BSWAP_32(value) _byteswap_ulong(value)
#define FLB_BSWAP_64(value) _byteswap_uint64(value)

#elif defined(FLB_HAVE_POSIX_BYTESWAP)
#define FLB_BSWAP_16(value) bswap_16(value)
#define FLB_BSWAP_32(value) bswap_32(value)
#define FLB_BSWAP_64(value) bswap_64(value)

#else

union flb_bswap_value_internal {
    char     raw[8];
    uint16_t word;
    uint32_t dword;
    uint64_t qword;
};

static inline uint16_t FLB_BSWAP_16(uint16_t value)
{
    union flb_bswap_value_internal output;
    union flb_bswap_value_internal input;

    output.word = value;
    input.word  = value;

    output.raw[0] = input.raw[1];
    output.raw[1] = input.raw[0];

    return output.word;
}

static inline uint32_t FLB_BSWAP_32(uint32_t value)
{
    union flb_bswap_value_internal output;
    union flb_bswap_value_internal input;

    output.dword = value;
    input.dword  = value;

    output.raw[0] = input.raw[3];
    output.raw[1] = input.raw[2];
    output.raw[2] = input.raw[1];
    output.raw[3] = input.raw[0];

    return output.dword;
}

static inline uint64_t FLB_BSWAP_64(uint64_t value)
{
    union flb_bswap_value_internal output;
    union flb_bswap_value_internal input;

    output.qword = value;
    input.qword  = value;

    output.raw[0] = input.raw[7];
    output.raw[1] = input.raw[6];
    output.raw[2] = input.raw[5];
    output.raw[3] = input.raw[4];
    output.raw[4] = input.raw[3];
    output.raw[5] = input.raw[2];
    output.raw[6] = input.raw[1];
    output.raw[7] = input.raw[0];

    return output.qword;
}

#endif

static inline uint32_t FLB_UINT32_TO_HOST_BYTE_ORDER(uint32_t value)
{
    #if FLB_BYTE_ORDER == FLB_LITTLE_ENDIAN
        return FLB_BSWAP_32(value);
    #else
        return value;
    #endif
}

#define FLB_UINT32_TO_NETWORK_BYTE_ORDER(value) FLB_UINT32_TO_HOST_BYTE_ORDER(value)

#endif
