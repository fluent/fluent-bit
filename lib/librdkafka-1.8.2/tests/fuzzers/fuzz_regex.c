/*
* librdkafka - Apache Kafka C library
*
* Copyright (c) 2020, Magnus Edenhill
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


/**
 * Fuzzer test case for the builtin regexp engine in src/regexp.c
 *
 * librdkafka must be built with --disable-regex-ext
 */

#include "rd.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "regexp.h"

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    /* wrap random data in a null-terminated string */
    char *null_terminated = malloc(size+1);
    memcpy(null_terminated, data, size);
    null_terminated[size] = '\0';

    const char *error;
    Reprog *p = re_regcomp(null_terminated, 0, &error);
    if (p != NULL) {
            re_regfree(p);
    }

    /* cleanup */
    free(null_terminated);

    return 0;
}

#if WITH_MAIN
#include "helpers.h"

int main (int argc, char **argv) {
        int i;
        for (i = 1 ; i < argc ; i++) {
                size_t size;
                uint8_t *buf = read_file(argv[i], &size);
                LLVMFuzzerTestOneInput(buf, size);
                free(buf);
        }
}
#endif
