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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_str.h>

#include <stdio.h>

char *flb_file_get_path(flb_file_handle handle)
{
    int ret;
    char *buf;
    ssize_t s;
    char tmp[128];

    buf = flb_calloc(sizeof(char), PATH_MAX);

    if (buf == NULL) {
        flb_errno();
        return NULL;
    }

    ret = snprintf(tmp, sizeof(tmp) - 1, "/proc/%i/fd/%i", getpid(), handle);
    if (ret == -1) {
        flb_errno();
        flb_free(buf);
        return NULL;
    }

    s = readlink(tmp, buf, PATH_MAX);

    if (s == -1) {
        flb_free(buf);
        flb_errno();
        return NULL;
    }

    buf[s] = '\0';

    return buf;
}
