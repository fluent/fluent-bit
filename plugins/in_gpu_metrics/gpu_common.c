/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "gpu_common.h"

int gpu_read_uint64(const char *path, uint64_t *value)
{
    FILE *fp;

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    if (fscanf(fp, "%" PRIu64, value) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int gpu_read_double(const char *path, double scale, double *value)
{
    uint64_t tmp;
    if (gpu_read_uint64(path, &tmp) != 0) {
        return -1;
    }
    *value = (double) tmp / scale;
    return 0;
}

int gpu_read_line(const char *path, char *buf, size_t size)
{
    FILE *fp;
    char *nl;

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    if (!fgets(buf, size, fp)) {
        fclose(fp);
        return -1;
    }
    // Remove newline
    nl = strchr(buf, '\n');
    if (nl) {
        *nl = '\0';
    }
    fclose(fp);
    return 0;
}
