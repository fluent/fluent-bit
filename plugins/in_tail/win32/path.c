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

#include <fluent-bit/flb_mem.h>

#include "interface.h"

wchar_t *win32_utf8_to_wide(const char *str)
{
    int len;
    wchar_t *buf;

    if (str == NULL) {
        return NULL;
    }

    len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                              str, -1, NULL, 0);
    if (len == 0) {
        return NULL;
    }

    buf = flb_calloc(len, sizeof(wchar_t));
    if (buf == NULL) {
        return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            str, -1, buf, len) == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}

char *win32_wide_to_utf8(const wchar_t *str)
{
    int len;
    char *buf;

    if (str == NULL) {
        return NULL;
    }

    len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                              str, -1, NULL, 0, NULL, NULL);
    if (len == 0) {
        return NULL;
    }

    buf = flb_calloc(len, sizeof(char));
    if (buf == NULL) {
        return NULL;
    }

    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                            str, -1, buf, len, NULL, NULL) == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}

char *win32_fullpath_utf8(const char *path)
{
    DWORD len;
    DWORD ret;
    wchar_t *wide_path;
    wchar_t *wide_fullpath;
    char *fullpath;

    wide_path = win32_utf8_to_wide(path);
    if (wide_path == NULL) {
        return NULL;
    }

    len = GetFullPathNameW(wide_path, 0, NULL, NULL);
    if (len == 0) {
        flb_free(wide_path);
        return NULL;
    }

    wide_fullpath = flb_calloc(len, sizeof(wchar_t));
    if (wide_fullpath == NULL) {
        flb_free(wide_path);
        return NULL;
    }

    ret = GetFullPathNameW(wide_path, len, wide_fullpath, NULL);
    flb_free(wide_path);

    if (ret == 0 || ret >= len) {
        flb_free(wide_fullpath);
        return NULL;
    }

    fullpath = win32_wide_to_utf8(wide_fullpath);
    flb_free(wide_fullpath);

    return fullpath;
}
