/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_MEM_H
#define FLB_MEM_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>

#ifdef FLB_HAVE_JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

#include <stdlib.h>

/*
 * The following memory handling wrappers, aims to simplify the way to use
 * the default memory allocator from the libc or an alternative one as Jemalloc.
 *
 * Here there is no error logging in case of failures, we defer that task to the
 * caller.
 */
#ifdef FLB_HAVE_ATTRIBUTE_ALLOC_SIZE
    #define FLB_ALLOCSZ_ATTR(x,...) __attribute__ ((alloc_size(x, ##__VA_ARGS__)))
#else
    #define FLB_ALLOCSZ_ATTR(x,...)
#endif

#ifdef FLB_HAVE_TESTS_OSSFUZZ
/*
 * Return 1 or 0 based on a probability.
 */
extern int flb_malloc_p;
extern int flb_malloc_mod;

static inline int flb_fuzz_get_probability(int val) {
  flb_malloc_p += 1;
  flb_malloc_p = flb_malloc_p % flb_malloc_mod;
  if (val > flb_malloc_p) {
    return 1;
  }
  return 0;
}
#endif

static inline FLB_ALLOCSZ_ATTR(1)
void *flb_malloc(const size_t size) {

#ifdef FLB_HAVE_TESTS_OSSFUZZ
   // 1% chance of failure
   if (flb_fuzz_get_probability(1)) {
     return NULL;
   }
#endif

    if (size == 0) {
        return NULL;
    }

    return malloc(size);
}

static inline FLB_ALLOCSZ_ATTR(1, 2)
void *flb_calloc(size_t n, const size_t size) {
    if (size == 0) {
        return NULL;
    }
#ifdef FLB_HAVE_TESTS_OSSFUZZ
   // Add chance of failure. Used by fuzzing to test error-handling code.
   if (flb_fuzz_get_probability(1)) {
     return NULL;
   }
#endif

    return calloc(n, size);
}

static inline FLB_ALLOCSZ_ATTR(2)
void *flb_realloc(void *ptr, const size_t size)
{
    return realloc(ptr, size);
}

static inline FLB_ALLOCSZ_ATTR(3)
void *flb_realloc_z(void *ptr, const size_t old_size, const size_t new_size)
{
    void *tmp;
    void *p;
    size_t diff;

    tmp = flb_realloc(ptr, new_size);
    if (!tmp) {
        return NULL;
    }

    if (new_size > old_size) {
        diff = new_size - old_size;
        p = ((char *) tmp + old_size);
        memset(p, 0, diff);
    }

    return tmp;
}


static inline void flb_free(void *ptr) {
    free(ptr);
}

#undef FLB_ALLOCSZ_ATTR

#endif
