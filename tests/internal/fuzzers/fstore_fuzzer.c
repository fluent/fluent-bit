/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_compat.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_utils.h>

#include <sys/types.h>
#include <sys/stat.h>


#define FSF_STORE_PATH "/tmp/flb-fstore"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int ret;
    void *out_buf;
    size_t out_size;
    struct stat st_data;
    struct flb_fstore *fs;
    struct flb_fstore_stream *st;
    struct flb_fstore_file *fsf;

    /* Set flb_malloc_mod to be fuzzer-data dependent */
    if (size < 4) {
        return 0;
    }
    flb_malloc_p = 0;
    flb_malloc_mod = *(int*)data;
    data += 4;
    size -= 4;

    /* Avoid division by zero for modulo operations */
    if (flb_malloc_mod == 0) {
        flb_malloc_mod = 1;
    }

    cio_utils_recursive_delete(FSF_STORE_PATH);
    fs = flb_fstore_create(FSF_STORE_PATH, FLB_FSTORE_FS);
    if (fs == NULL) {
        return 0;
    }
    st = flb_fstore_stream_create(fs, "abc");
    if (st != NULL) {
        fsf = flb_fstore_file_create(fs, st, "example.txt", size);

        if (fsf != NULL) {
            ret = flb_fstore_file_append(fsf, data, size);
            if (ret == 0) {
                ret = flb_fstore_file_content_copy(fs, fsf, &out_buf, &out_size);
                if (ret == 0) {
                    assert(memcmp(out_buf, data, size) == 0);
                }
                flb_free(out_buf);
            }
        }
    }

    flb_fstore_dump(fs);
    flb_fstore_destroy(fs);
    return 0;
}
