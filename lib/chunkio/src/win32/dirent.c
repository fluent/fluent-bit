/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018-2019 Eduardo Silva <eduardo@monkey.io>
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

/*
 * This module implements <dirent.h> emulation layer based on
 * Win32's FIndFirstFile/FindNextFile API.
 */

#include <Windows.h>
#include <shlwapi.h>

#include "dirent.h"

struct CIO_WIN32_DIR {
    HANDLE h;
    char *pattern;
    int count;
    WIN32_FIND_DATA find_data;
    struct cio_win32_dirent dir;
};

/*
 * Guess POSIX flle type from Win32 file attributes.
 */
static int get_filetype(int dwFileAttributes)
{
    if (dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        return DT_DIR;
    }
    else if (dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        return DT_LNK;
    }
    return DT_REG;
}

/*
 * Construct a match pattern (e.g. 'c:\var\data\*')
 */
static char *create_pattern(const char *path)
{
    char *buf;
    int len = strlen(path);
    int buflen = len + 3;

    buf = malloc(buflen);
    if (buf == NULL) {
        return NULL;
    }

    strcpy_s(buf, buflen, path);

    if (path[len - 1] == '\\') {
        strcat_s(buf, buflen, "*");
    }
    else {
        strcat_s(buf, buflen, "\\*");
    }
    return buf;
}

struct CIO_WIN32_DIR *cio_win32_opendir(const char *path)
{
    struct CIO_WIN32_DIR *d;

    if (!PathIsDirectoryA(path)) {
        return NULL;
    }

    d = calloc(1, sizeof(struct CIO_WIN32_DIR));
    if (d == NULL) {
        return NULL;
    }

    d->pattern = create_pattern(path);
    if (d->pattern == NULL) {
        return NULL;
    }

    d->h = FindFirstFileA(d->pattern, &d->find_data);
    if (d->h == INVALID_HANDLE_VALUE) {
        return d;
    }
    return d;
}

struct cio_win32_dirent *cio_win32_readdir(struct CIO_WIN32_DIR *d)
{
    if (d->h == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    /*
     * The initial entry should be retrieved by FindFirstFile(),
     * so we can skip FindNextFile() on the first call.
     */
    if (d->count > 0) {
        if (FindNextFile(d->h, &d->find_data) == 0) {
            return NULL;
        }
    }

    d->count++;
    d->dir.d_name = d->find_data.cFileName;
    d->dir.d_type = get_filetype(d->find_data.dwFileAttributes);

    return &d->dir;
}

int cio_win32_closedir(struct CIO_WIN32_DIR *d)
{
    if (d->h != INVALID_HANDLE_VALUE) {
        FindClose(d->h);
    }
    free(d->pattern);
    free(d);
    return 0;
}
