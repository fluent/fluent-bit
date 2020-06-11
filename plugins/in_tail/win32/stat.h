/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#ifndef FLB_TAIL_WIN32_STAT_H
#define FLB_TAIL_WIN32_STAT_H

struct win32_stat {
   uint64_t st_ino;
   uint16_t st_mode;
   int32_t  st_nlink;
   int64_t  st_size;
};

int win32_stat(const char *path, struct win32_stat *wst);
int win32_lstat(const char *path, struct win32_stat *wst);
int win32_fstat(const char *path, struct win32_stat *wst);

#define WIN32_S_IFDIR 0x1000
#define WIN32_S_IFCHR 0x2000
#define WIN32_S_IFIFO 0x4000
#define WIN32_S_IFREG 0x8000
#define WIN32_S_IFLNK 0xc000
#define WIN32_S_IFMT  0xf000

#endif
