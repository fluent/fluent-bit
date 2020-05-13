/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <monkey/mk_core.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/* declare external function test */
int LLVMFuzzerTestOneInput(unsigned char *data, size_t size);

int main(int argc, char **argv)
{
    int i;
    int ret;
    FILE *fp;
    char *buffer;
    long bytes;
    struct stat st;

    if (argc < 2) {
        flb_error("usage: %s TESTCASE_FILE", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Validate the file */
    ret = stat(argv[1], &st);
    if (ret == -1) {
        flb_errno();
        flb_error("cannot stat(2) testcase file '%s'", argv[1]);
        exit(EXIT_FAILURE);
    }

    if (!(fp = fopen(argv[1], "rb"))) {
        flb_errno();
        flb_error("cannot fopen(2) testcase file '%s'", argv[1]);
        return -1;
    }

    buffer = flb_malloc(st.st_size);
    if (!buffer) {
        flb_errno();
        return -1;
    }

    bytes = fread(buffer, st.st_size, 1, fp);
    if (bytes < 1) {
        fclose(fp);
        flb_free(buffer);
        return -1;
    }
    fclose(fp);

    /* Invoke the fuzzer entry-point function */
    for (i = 0; i < 1; i++) {
        ret = LLVMFuzzerTestOneInput((unsigned char *) buffer, st.st_size);
    }
    flb_free(buffer);
    return 0;
}
