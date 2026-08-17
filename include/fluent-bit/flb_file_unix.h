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

#ifndef FLB_FILE_UNIX_H
#define FLB_FILE_UNIX_H

#define FLB_FILE_IFMT  S_IFMT
#define FLB_FILE_IFIFO S_IFIFO
#define FLB_FILE_IFCHR S_IFCHR
#define FLB_FILE_IFDIR S_IFDIR
#define FLB_FILE_IFBLK S_IFBLK
#define FLB_FILE_IFREG S_IFREG
#define FLB_FILE_IFLNK S_IFLNK

#define FLB_FILE_ISDIR(m)  S_ISDIR(m)
#define FLB_FILE_ISCHR(m)  S_ISCHR(m)
#define FLB_FILE_ISFIFO(m) S_ISFIFO(m)
#define FLB_FILE_ISREG(m)  S_ISREG(m)
#define FLB_FILE_ISLNK(m)  S_ISLNK(m)

#define FLB_FILE_INVALID_HANDLE  (-1)
#define FLB_FILE_MAX_PATH_LENGTH PATH_MAX

typedef int flb_file_handle;

#endif
