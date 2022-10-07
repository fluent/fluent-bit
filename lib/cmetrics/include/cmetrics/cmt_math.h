/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#ifndef CMT_MATH_H
#define CMT_MATH_H

#include <inttypes.h>
#include <string.h>

union val_union {
    uint64_t u;
    double d;
};

/*
 * This is not rocket-science and to make things easier we assume that operating on
 * floating pointer numbers we will lose precision. So we just do simple casts.
 */

static inline uint64_t cmt_math_d64_to_uint64(double val)
{
    union val_union u;

    u.d = val;
    return u.u;
}

static inline double cmt_math_uint64_to_d64(uint64_t val)
{
    union val_union u;

    u.u = val;
    return u.d;
}

#endif
