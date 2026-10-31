/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2026 The Fluent Bit Authors
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

/* Internal, overflow-checked allocation calculations shared by both backends. */
#ifndef CIO_SIZE_H
#define CIO_SIZE_H

#include <stdint.h>
#include <stddef.h>
#include <chunkio/chunkio.h>

static inline int cio_size_round(size_t size, size_t alignment, size_t *out)
{
    size_t remainder;
    size_t padding;

    if (alignment == 0 || size > PTRDIFF_MAX) {
        return CIO_ERROR;
    }

    remainder = size % alignment;
    padding = 0;

    if (remainder != 0) {
        padding = alignment - remainder;
    }

    if (padding > PTRDIFF_MAX - size) {
        return CIO_ERROR;
    }

    *out = size + padding;

    return CIO_OK;
}

static inline int cio_size_grow(size_t current, size_t required, size_t step,
                               size_t alignment, int adaptive, size_t *out)
{
    size_t candidate;
    size_t increment;
    size_t delta;
    size_t remainder;
    size_t padding;

    if (required > PTRDIFF_MAX || current > PTRDIFF_MAX || step == 0) {
        return CIO_ERROR;
    }

    if (required <= current) {
        *out = current;
        return CIO_OK;
    }

    /* Grow by half the current capacity, up to the adaptive increment limit. */
    if (adaptive) {
        increment = current / 2;

        if (increment > CIO_ADAPTIVE_GROWTH_MAX) {
            increment = CIO_ADAPTIVE_GROWTH_MAX;
        }

        /* Respect an explicitly configured step larger than the adaptive one. */
        if (increment > step) {
            step = increment;
        }
    }

    /* Cover the append in one allocation, without looping over increments. */
    delta = required - current;
    remainder = delta % step;
    padding = 0;

    if (remainder != 0) {
        padding = step - remainder;
    }

    if (padding <= PTRDIFF_MAX - required) {
        candidate = required + padding;

        if (cio_size_round(candidate, alignment, out) == CIO_OK) {
            return CIO_OK;
        }
    }

    /* Optional headroom must not overflow an otherwise representable size. */
    return cio_size_round(required, alignment, out);
}

#endif
