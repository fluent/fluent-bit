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

/*
 * This is the interface file that replaces POSIX functions
 * with our own custom implementation.
 */

#ifndef FLB_TAIL_WIN32_H
#define FLB_TAIL_WIN32_H

#include "win32/interface.h"

#undef open
#undef stat
#undef lstat
#undef fstat
#undef lseek

#undef S_IFDIR
#undef S_IFCHR
#undef S_IFIFO
#undef S_IFREG
#undef S_IFLNK
#undef S_IFMT
#undef S_ISDIR
#undef S_ISCHR
#undef S_ISFIFO
#undef S_ISREG
#undef S_ISLNK

#define open win32_open
#define stat win32_stat
#define lstat win32_lstat
#define fstat win32_fstat

#define lseek _lseeki64

#define S_IFDIR WIN32_S_IFDIR
#define S_IFCHR WIN32_S_IFCHR
#define S_IFIFO WIN32_S_IFIFO
#define S_IFREG WIN32_S_IFREG
#define S_IFLNK WIN32_S_IFLNK
#define S_IFMT  WIN32_S_IFMT

#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif
