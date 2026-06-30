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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <io.h>
#include <errno.h>

#include <fluent-bit/flb_mem.h>

#include "interface.h"

/*
 * POSIX IO emulation tailored for in_tail's usage.
 *
 * open(2) that does not acquire an exclusive lock.
 */

int win32_open(const char *path, int flags)
{
    HANDLE h;
    h = CreateFileA(path,
                    GENERIC_READ,
                    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                    NULL,           /* lpSecurityAttributes */
                    OPEN_EXISTING,  /* dwCreationDisposition */
                    0,              /* dwFlagsAndAttributes */
                    NULL);          /* hTemplateFile */
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }
    return _open_osfhandle((intptr_t) h, _O_RDONLY);
}

int win32_open_utf8(const char *path, int flags)
{
    HANDLE h;
    wchar_t *wide_path;

    wide_path = win32_utf8_to_wide(path);
    if (wide_path == NULL) {
        errno = EINVAL;
        return -1;
    }

    h = CreateFileW(wide_path,
                    GENERIC_READ,
                    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                    NULL,           /* lpSecurityAttributes */
                    OPEN_EXISTING,  /* dwCreationDisposition */
                    0,              /* dwFlagsAndAttributes */
                    NULL);          /* hTemplateFile */

    if (h == INVALID_HANDLE_VALUE) {
        win32_propagate_last_error_to_errno();
        flb_free(wide_path);
        return -1;
    }

    flb_free(wide_path);
    return _open_osfhandle((intptr_t) h, _O_RDONLY);
}
