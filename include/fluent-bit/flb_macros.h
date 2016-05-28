/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#define FLB_FALSE  0
#define FLB_TRUE   !FLB_FALSE

#define FLB_INLINE inline __attribute__((always_inline))

#if __GNUC__ >= 4
 #define FLB_EXPORT __attribute__ ((visibility ("default")))
#else
 #define FLB_EXPORT
#endif


#define flb_unlikely(x) __builtin_expect((x),0)
#define flb_likely(x)   __builtin_expect((x),1)

#define flb_bug(condition) do {                                         \
        if (flb_unlikely((condition)!=0)) {                             \
            fprintf(stderr, "Bug found in %s() at %s:%d",               \
                    __FUNCTION__, __FILE__, __LINE__);                  \
            abort();                                                    \
        }                                                               \
    } while(0)
#endif
