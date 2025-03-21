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

#ifndef FLB_WE_UTIL_H
#define FLB_WE_UTIL_H

#include "we.h"

#define WE_VERSION_REGISTRY_PATH \
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

#define WE_VERSION_KEY_NAME      "CurrentVersion"

int we_get_windows_version(double *version_number);
void we_hexdump(uint8_t *buffer, size_t buffer_length, size_t line_length);
/* Utilites for char/wchar_t conversion */
wchar_t* we_convert_str(char *str);
char* we_convert_wstr(wchar_t *wstr, UINT codePage);

#endif
