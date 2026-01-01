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

#ifndef FLB_MACROS_H
#define FLB_MACROS_H

#include <stdbool.h>
#include <monkey/mk_core.h>

#define FLB_FALSE  false
#define FLB_TRUE   true

/* Return values */
#define FLB_ERROR   0
#define FLB_OK      1
#define FLB_RETRY   2

/* ala-printf format check */
#if defined(__GNUC__) || defined(__clang__)
#define FLB_FORMAT_PRINTF(fmt, args) __attribute__ ((format (printf, fmt, args)))
#else
#define FLB_FORMAT_PRINTF(fmt, args)
#endif

#ifdef _WIN32
#define FLB_INLINE inline
#else
#define FLB_INLINE inline __attribute__((always_inline))
#endif

#define FLB_EXPORT MK_EXPORT

#define flb_unlikely(x) mk_unlikely(x)
#define flb_likely(x)   mk_likely(x)

#define flb_bug(condition) do {                                         \
        if (flb_unlikely((condition)!=0)) {                             \
            fprintf(stderr, "Bug found in %s() at %s:%d",               \
                    __FUNCTION__, __FILE__, __LINE__);                  \
            abort();                                                    \
        }                                                               \
    } while(0)
#endif
