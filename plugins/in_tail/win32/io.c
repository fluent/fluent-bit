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
#include <errno.h>
#include <limits.h>
#include <stdio.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_mem.h>

#include "interface.h"

HANDLE win32_open(const char *path, int utf8)
{
    HANDLE handle;
    wchar_t *wide_path;
    DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    if (utf8) {
        wide_path = win32_utf8_to_wide(path);
        if (wide_path == NULL) {
            errno = EINVAL;
            return INVALID_HANDLE_VALUE;
        }

        handle = CreateFileW(wide_path, GENERIC_READ, share, NULL, OPEN_EXISTING, 0, NULL);
        if (handle == INVALID_HANDLE_VALUE) {
            win32_propagate_last_error_to_errno();
        }
        flb_free(wide_path);
        return handle;
    }

    handle = CreateFileA(path, GENERIC_READ, share, NULL, OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        win32_propagate_last_error_to_errno();
    }
    return handle;
}

ssize_t win32_read(HANDLE handle, void *buffer, size_t size)
{
    DWORD requested;
    DWORD bytes_read;
    DWORD error;

    requested = size > INT_MAX ? INT_MAX : (DWORD) size;
    if (ReadFile(handle, buffer, requested, &bytes_read, NULL)) {
        return bytes_read;
    }
    error = GetLastError();
    if (error == ERROR_HANDLE_EOF) {
        return 0;
    }

    if (error == ERROR_LOCK_VIOLATION) {
        /* Match CRT read semantics so Tail retries a locked byte range. */
        errno = EACCES;
        return -1;
    }

    win32_propagate_last_error_to_errno();
    return -1;
}

int64_t win32_seek(HANDLE handle, int64_t offset, int whence)
{
    DWORD method;
    LARGE_INTEGER distance;
    LARGE_INTEGER position;

    switch (whence) {
    case SEEK_SET:
        method = FILE_BEGIN;
        break;
    case SEEK_CUR:
        method = FILE_CURRENT;
        break;
    case SEEK_END:
        method = FILE_END;
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    distance.QuadPart = offset;
    if (!SetFilePointerEx(handle, distance, &position, method)) {
        win32_propagate_last_error_to_errno();
        return -1;
    }

    return position.QuadPart;
}
