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

#ifndef FLB_FILE_WIN32_H
#define FLB_FILE_WIN32_H

#define FLB_FILE_IFMT  0170000
#define FLB_FILE_IFIFO 0010000
#define FLB_FILE_IFCHR 0020000
#define FLB_FILE_IFDIR 0040000
#define FLB_FILE_IFBLK 0060000
#define FLB_FILE_IFREG 0100000
#define FLB_FILE_IFLNK 0120000

#define FLB_FILE_ISTYPE(m, t) (((m) & FLB_FILE_IFMT) == t)
#define FLB_FILE_ISDIR(m)     (FLB_FILE_ISTYPE(m, FLB_FILE_IFDIR))
#define FLB_FILE_ISCHR(m)     (FLB_FILE_ISTYPE(m, FLB_FILE_IFCHR))
#define FLB_FILE_ISFIFO(m)    (FLB_FILE_ISTYPE(m, FLB_FILE_IFIFO))
#define FLB_FILE_ISREG(m)     (FLB_FILE_ISTYPE(m, FLB_FILE_IFREG))
#define FLB_FILE_ISLNK(m)     (FLB_FILE_ISTYPE(m, FLB_FILE_IFLNK))

#define FLB_FILE_INVALID_HANDLE  (INVALID_HANDLE_VALUE)
#define FLB_FILE_MAX_PATH_LENGTH MAX_PATH

typedef HANDLE flb_file_handle;

#endif
