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

int flb_pack_json(char*, int, char**, size_t*, int*);

int LLVMFuzzerTestOneInput(unsigned char *data, size_t size)
{
    /* json packer */
    char *out_buf = NULL;
    size_t out_size;
    int root_type;
    int ret = flb_pack_json((char*)data, size, &out_buf, &out_size, &root_type);

    if (ret == 0) {
        free(out_buf);
    }

    return 0;
}
