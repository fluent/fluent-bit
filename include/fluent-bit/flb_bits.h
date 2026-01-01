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

#ifndef FLB_BITS_H
#define FLB_BITS_H

#define FLB_BITS_U64_SET(a, b)   ((uint64_t) a << 32 | b)
#define FLB_BITS_U64_HIGH(val)   ((uint64_t) val >> 32)
#define FLB_BITS_U64_LOW(val)    ((uint64_t) val & 0xffffffff)
#define FLB_BITS_CLEAR(val, n)   (val & ~(1 << n))
#define FLB_BIT_MASK(__TYPE__, __ONE_COUNT__)   \
    ((__TYPE__) (-((__ONE_COUNT__) != 0)))                              \
    & (((__TYPE__) -1) >> ((sizeof(__TYPE__) * CHAR_BIT) - (__ONE_COUNT__)))

#endif
