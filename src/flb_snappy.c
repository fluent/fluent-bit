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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <snappy.h>

int flb_snappy_compress(void *in_data, size_t in_len,
                        void **out_data, size_t *out_len)
{
    struct snappy_env snappy_env;
    char             *tmp_data;
    size_t            tmp_len;
    int               result;

    tmp_len = snappy_max_compressed_length(in_len);

    tmp_data = flb_malloc(tmp_len);

    if (tmp_data == NULL) {
        flb_errno();

        return -1;
    }

    result = snappy_init_env(&snappy_env);

    if (result != 0) {
        flb_free(tmp_data);

        return -2;
    }

    result = snappy_compress(&snappy_env, in_data, in_len, tmp_data, &tmp_len);

    if (result != 0) {
        flb_free(tmp_data);

        return -3;
    }

    snappy_free_env(&snappy_env);

    *out_data = tmp_data;
    *out_len = tmp_len;

    return 0;
}

int flb_snappy_uncompress(void *in_data, size_t in_len,
                          void **out_data, size_t *out_len)
{
    char             *tmp_data;
    size_t            tmp_len;
    int               result;

    result = snappy_uncompressed_length(in_data, in_len, &tmp_len);

    if (result == 0) {
        return -1;
    }

    tmp_data = flb_malloc(tmp_len);

    if (tmp_data == NULL) {
        flb_errno();

        return -2;
    }

    result = snappy_uncompress(in_data, in_len, tmp_data);

    if (result != 0) {
        flb_free(tmp_data);

        return -3;
    }

    *out_data = tmp_data;
    *out_len = tmp_len;

    return 0;
}
