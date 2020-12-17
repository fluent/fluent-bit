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
#include <stdlib.h>
#include <stdint.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>

int LLVMFuzzerTestOneInput(unsigned char *data, size_t size)
{
    /* json packer */
    char *out_buf = NULL;
    size_t out_size;
    int root_type;
    int ret = flb_pack_json((char*)data, size, &out_buf, &out_size, &root_type);

    if (ret == 0) {
        size_t off = 0;
        msgpack_unpacked result;
        msgpack_unpacked_init(&result);
        int ret2 = msgpack_unpack_next(&result, out_buf, out_size, &off);
        if (ret2 == MSGPACK_UNPACK_SUCCESS) {
            msgpack_object root = result.data;
            flb_msgpack_to_json_str(0, &root);
        }

        flb_pack_msgpack_to_json_format(out_buf, out_size,
                FLB_PACK_JSON_FORMAT_LINES,
                FLB_PACK_JSON_DATE_EPOCH, NULL);
        free(out_buf);
    }

    return 0;
}
