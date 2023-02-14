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

#ifdef _WIN32
#include <Shlobj.h>
#endif

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

#ifdef _WIN32
    char path[MAX_PATH];
#else
# ifdef __APPLE__
    char *parent_dir = NULL;
    char *path = NULL;
# endif
    char *dup_dir;
#endif

    if (!dir) {
        errno = EINVAL;
        return 1;
    }

    if (strlen(dir) == 0) {
        errno = EINVAL;
        return 1;
    }

    if (!stat(dir, &st)) {
        return 0;
    }

#ifdef _WIN32
    (void) mode;

    if (_fullpath(path, dir, MAX_PATH) == NULL) {
        return 1;
    }

    if (SHCreateDirectoryExA(NULL, path, NULL) != ERROR_SUCCESS) {
        return 1;
    }
    return 0;
#elif __APPLE__
    dup_dir = strdup(dir);
    if (!dup_dir) {
        return -1;
    }

    /* macOS's dirname(3) should return current directory when slash
     * charachter is not included in passed string.
     * And note that macOS's dirname(3) does not modify passed string.
     */
    parent_dir = dirname(dup_dir);
    if (stat(parent_dir, &st) == 0 && strncmp(parent_dir, ".", 1)) {
        if (S_ISDIR (st.st_mode)) {
            mkdir(dup_dir, mode);
            free(dup_dir);
            return 0;
        }
    }

    /* Create directories straightforward except for the last one hierarchy. */
    for (path = strchr(dup_dir + 1, '/'); path; path = strchr(path + 1, '/')) {
        *path = '\0';
        if (mkdir(dup_dir, mode) == -1) {
            if (errno != EEXIST) {
                *path = '/';
                return -1;
            }
        }
        *path = '/';
    }

    free(dup_dir);
    return mkdir(dir, mode);
#else
    dup_dir = strdup(dir);
    if (!dup_dir) {
        return 1;
    }
    cio_os_mkpath(dirname(dup_dir), mode);
    free(dup_dir);
    return mkdir(dir, mode);
#endif
}
