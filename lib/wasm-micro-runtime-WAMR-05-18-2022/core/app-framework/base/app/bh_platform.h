/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef DEPS_IWASM_APP_LIBS_BASE_BH_PLATFORM_H_
#define DEPS_IWASM_APP_LIBS_BASE_BH_PLATFORM_H_

#include <stdbool.h>

typedef unsigned char uint8;
typedef char int8;
typedef unsigned short uint16;
typedef short int16;
typedef unsigned int uint32;
typedef int int32;

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef __cplusplus
#define true 1
#define false 0
#define inline __inline
#endif

// all wasm-app<->native shared source files should use WA_MALLOC/WA_FREE.
// they will be mapped to different implementations in each side
#ifndef WA_MALLOC
#define WA_MALLOC malloc
#endif

#ifndef WA_FREE
#define WA_FREE free
#endif

uint32
htonl(uint32 value);
uint32
ntohl(uint32 value);
uint16
htons(uint16 value);
uint16
ntohs(uint16 value);

// We are not worried for the WASM world since the sandbox will catch it.
#define bh_memcpy_s(dst, dst_len, src, src_len) memcpy(dst, src, src_len)

#ifdef NDEBUG
#define bh_assert(v) (void)0
#else
#define bh_assert(v)                                                     \
    do {                                                                 \
        if (!(v)) {                                                      \
            int _count;                                                  \
            printf("ASSERTION FAILED: %s, at %s, line %d", #v, __FILE__, \
                   __LINE__);                                            \
            _count = printf("\n");                                       \
            printf("%d\n", _count / (_count - 1));                       \
        }                                                                \
    } while (0)
#endif

#endif /* DEPS_IWASM_APP_LIBS_BASE_BH_PLATFORM_H_ */
