/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <chunkio/chunkio_compat.h>

/* Check if a path is a directory */
int cio_os_isdir(const char *dir)
{
    int ret;
    struct stat st;

    ret = stat(dir, &st);
    if (ret == -1) {
        return -1;
    }

    if (st.st_mode & S_IFDIR) {
        return 0;
    }

    return -1;
}

/* Create directory */
int cio_os_mkpath(const char *dir, mode_t mode)
{
    struct stat st;
    char *dup_dir = NULL;

    if (!dir) {
        errno = EINVAL;
        return 1;
    }

    if (!stat(dir, &st)) {
        return 0;
    }

    dup_dir = strdup(dir);
    if (!dup_dir) {
        return 1;
    }
    cio_os_mkpath(dirname(dup_dir), mode);
    free(dup_dir);
    return mkdir(dir, mode);
}
