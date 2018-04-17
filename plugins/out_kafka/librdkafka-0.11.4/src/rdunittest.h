/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2017 Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RD_UNITTEST_H
#define _RD_UNITTEST_H

#include <stdio.h>


/**
 * @brief Fail the current unit-test function.
 */
#define RD_UT_FAIL(...) do {                                            \
                fprintf(stderr, "\033[31mRDUT: FAIL: %s:%d: %s: ",      \
                        __FILE__, __LINE__, __FUNCTION__);              \
                fprintf(stderr, __VA_ARGS__);                           \
                fprintf(stderr, "\033[0m\n");                           \
                return 1;                                               \
        } while (0)

/**
 * @brief Pass the current unit-test function
 */
#define RD_UT_PASS() do {                                               \
                fprintf(stderr, "\033[32mRDUT: PASS: %s:%d: %s\033[0m\n", \
                        __FILE__, __LINE__, __FUNCTION__);              \
                return 0;                                               \
        } while (0)

/**
 * @brief Fail unit-test if \p expr is false
 */
#define RD_UT_ASSERT(expr,...) do {                                     \
        if (!(expr)) {                                                  \
        fprintf(stderr,                                                 \
                "\033[31mRDUT: FAIL: %s:%d: %s: assert failed: " # expr ": ", \
                __FILE__, __LINE__, __FUNCTION__);                      \
        fprintf(stderr, __VA_ARGS__);                                   \
        fprintf(stderr, "\033[0m\n");                                   \
        return 1;                                                       \
        }                                                               \
         } while (0)


/**
 * @brief Log something from a unit-test
 */
#define RD_UT_SAY(...) do {                                             \
                fprintf(stderr, "RDUT: INFO: %s:%d: %s: ",              \
                        __FILE__, __LINE__, __FUNCTION__);              \
                fprintf(stderr, __VA_ARGS__);                           \
                fprintf(stderr, "\n");                                  \
        } while (0)


int rd_unittest (void);

#endif /* _RD_UNITTEST_H */
