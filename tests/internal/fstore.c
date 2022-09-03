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
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_compat.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_utils.h>

#include "flb_tests_internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#ifdef FLB_SYSTEM_WINDOWS
/* Not yet implemented! */
#else
#define FSF_STORE_PATH "/tmp/flb-fstore"
#endif

void cb_all()
{
    int ret;
    void *out_buf;
    size_t out_size;
    struct stat st_data;
    struct flb_fstore *fs;
    struct flb_fstore_stream *st;
    struct flb_fstore_file *fsf;

    cio_utils_recursive_delete(FSF_STORE_PATH);

    fs = flb_fstore_create(FSF_STORE_PATH, FLB_FSTORE_FS);
    TEST_CHECK(fs != NULL);

    st = flb_fstore_stream_create(fs, "abc");
    TEST_CHECK(st != NULL);

    fsf = flb_fstore_file_create(fs, st, "example.txt", 100);
    TEST_CHECK(fsf != NULL);
    if (!fsf) {
        return;
    }

    ret = stat(FSF_STORE_PATH "/abc/example.txt", &st_data);
    TEST_CHECK(ret == 0);

    ret = flb_fstore_file_append(fsf, "fluent-bit\n", 11);
    TEST_CHECK(ret == 0);

    ret = flb_fstore_file_content_copy(fs, fsf, &out_buf, &out_size);
    TEST_CHECK(ret == 0);

    TEST_CHECK(memcmp(out_buf, "fluent-bit\n", 11) == 0);
    TEST_CHECK(out_size == 11);
    flb_free(out_buf);

    flb_fstore_dump(fs);
    flb_fstore_destroy(fs);
}

TEST_LIST = {
    { "all" , cb_all},
    { NULL }
};
