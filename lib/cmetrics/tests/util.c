/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#include <stdio.h>

#include <cmetrics/cmetrics.h>

cfl_sds_t read_file(const char *path)
{
    long flen;
    FILE *f = NULL;
    cfl_sds_t result = NULL;

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

    result = cfl_sds_create_size(flen);
    if (!result) {
        goto err;
    }

    if (flen > 0 && fread(result, flen, 1, f) != 1) {
        goto err;
    }

    cfl_sds_set_len(result, flen);
    fclose(f);
    return result;

err:
    fclose(f);
    if (result) {
        cfl_sds_destroy(result);
    }
    return NULL;
}

