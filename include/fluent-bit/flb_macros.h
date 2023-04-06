/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <monkey/mk_core.h>

#define FLB_FALSE  0
#define FLB_TRUE   !FLB_FALSE

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

#define FLB_DEBUG_TRACE() fprintf(stderr, "DEBUG TRACE : %s - %s - %d\n", __FILE__, __FUNCTION__, __LINE__);
#define FLB_DEBUG_TRACE_PRINT(fmt, ...) fprintf(stderr, "DEBUG TRACE : %s - %s - %d - " fmt "\n", __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);

#define FLB_DUMP_BINARY_SEQ(filename_format, buffer, length)    {                                                                            \
                                                                    static size_t flb_fn_idx = 0;                                            \
                                                                    char flb_fn_tmp[255];                                                    \
                                                                    snprintf(flb_fn_tmp, sizeof(flb_fn_tmp), filename_format, flb_fn_idx++); \
                                                                    FLB_DUMP_BINARY(flb_fn_tmp, buffer, length);                             \
                                                                }

#define FLB_DUMP_BINARY(filename, buffer, length)   {                                                                                             \
                                                        size_t flb_db_wtn;                                                                        \
                                                        FILE *flb_db_tmp;                                                                         \
                                                        flb_db_tmp = fopen(filename, "wb+");                                                      \
                                                        if (flb_db_tmp == NULL) {                                                                 \
                                                            printf(stderr, "DLB_DUMP_BINARY : could not open %s\n", filename);                    \
                                                        }                                                                                         \
                                                        else {                                                                                    \
                                                            flb_db_wtn = fwrite(buffer, sizeof(typeof(*buffer)), length, flb_db_tmp);             \
                                                            fprintf(stderr, "FLB_DUMP_BINARY : written %zu bytes to %s\n", flb_db_wtn, filename); \
                                                            fclose(flb_db_tmp);                                                                   \
                                                        }                                                                                         \
                                                    }

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
