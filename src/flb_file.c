/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>

#include <stdio.h>

flb_sds_t flb_file_read(const char *path)
{
    long flen;
    FILE *f = NULL;
    flb_sds_t result = NULL;

    f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) == -1) {
        goto err;
    }

    flen = ftell(f);
    if (flen < 0) {
        goto err;
    }

    if (fseek(f, 0, SEEK_SET) == -1) {
        goto err;
    }

    result = flb_sds_create_size(flen);
    if (!result) {
        goto err;
    }

    if (flen > 0 && fread(result, flen, 1, f) != 1) {
        goto err;
    }

    result[flen] = 0;
    flb_sds_len_set(result, flen);
    fclose(f);
    return result;

err:
    flb_errno();
    fclose(f);
    if (result) {
        flb_sds_destroy(result);
    }
    return NULL;
}
