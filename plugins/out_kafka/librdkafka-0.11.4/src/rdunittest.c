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

#include "rd.h"
#include "rdunittest.h"

#include "rdvarint.h"
#include "rdbuf.h"
#include "crc32c.h"
#include "rdmurmur2.h"
#include "rdkafka_int.h"


int rd_unittest (void) {
        int fails = 0;
        const struct {
                const char *name;
                int (*call) (void);
        } unittests[] = {
                { "rdbuf",    unittest_rdbuf },
                { "rdvarint", unittest_rdvarint },
                { "crc32c",   unittest_crc32c },
                { "msg",      unittest_msg },
                { "murmurhash", unittest_murmur2 },
                { NULL }
        };
        int i;

        for (i = 0 ; unittests[i].name ; i++) {
                int f = unittests[i].call();
                RD_UT_SAY("unittest: %s: %4s\033[0m",
                          unittests[i].name,
                          f ? "\033[31mFAIL" : "\033[32mPASS");
                fails += f;
        }

        return fails;
}
