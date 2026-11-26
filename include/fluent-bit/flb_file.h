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

#ifndef FLB_FILE_H
#define FLB_FILE_H

#include <fluent-bit/flb_sds.h>
#include <stdio.h>
#ifdef FLB_SYSTEM_WINDOWS
#include <fluent-bit/flb_compat.h>
#endif

flb_sds_t flb_file_read(const char *path);
/*
 * Open a regular file without following symlinks (or Windows reparse points)
 * in any path component. POSIX callers may also open a directory with O_DIRECTORY.
 * With root != NULL, path must be relative and stay beneath root.
 * Parent traversal is rejected. mkdir_mode != 0 creates missing parents.
 */
int flb_file_open_safe(const char *root, const char *path, int flags,
                       int mode, int mkdir_mode);
FILE *flb_file_fopen_safe(const char *root, const char *path, const char *mode,
                          int mkdir_mode);
int flb_file_mkdir_safe(const char *path, int mode);
int flb_file_rename_safe(const char *source, const char *destination);
int flb_file_unlink_safe(const char *path);
#ifdef FLB_SYSTEM_WINDOWS
/* Apply the same path checks and return a handle owned by the caller. */
HANDLE flb_file_open_safe_for_read(const char *path, UINT code_page);
int flb_file_open_safe_utf8(const char *path, int flags);
int flb_file_remove_tree_safe(const char *path);
#endif
// TODO int flb_file_write(const char *path, flb_sds_t contents);

#endif
