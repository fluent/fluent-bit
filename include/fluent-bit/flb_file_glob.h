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

#ifndef FLB_FILE_GLOB_H
#define FLB_FILE_GLOB_H

#include <fluent-bit/flb_info.h>

#define FLB_FILE_GLOB_SUCCESS        0
#define FLB_FILE_GLOB_NO_MATCHES     1
#define FLB_FILE_GLOB_NO_MEMORY     2
#define FLB_FILE_GLOB_ABORTED       3
#define FLB_FILE_GLOB_INVALID_PATH  4

#define FLB_FILE_GLOB_EXPAND_TILDE   (1U << 0)
#define FLB_FILE_GLOB_WINDOWS_UTF8   (1U << 1)

typedef void (*flb_file_glob_callback)(char *path, void *data);

/* Visit matching paths in platform scan order. A path is valid during the callback.
 * POSIX can expand a leading tilde. Windows expands star patterns component by
 * component and uses the ANSI code page unless FLB_FILE_GLOB_WINDOWS_UTF8 is set.
 */
int flb_file_glob(const char *pattern, unsigned int flags,
                  flb_file_glob_callback callback, void *data);

#ifdef FLB_SYSTEM_WINDOWS
#include <wchar.h>

wchar_t *flb_file_win32_utf8_to_wide(const char *str);
char *flb_file_win32_wide_to_utf8(const wchar_t *str);
#endif

#endif
