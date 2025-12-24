/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_GLOB_WIN32_H
#define FLB_GLOB_WIN32_H

#include <fluent-bit/flb_info.h>
#include <sys/stat.h>
#include <limits.h>

#ifdef FLB_SYSTEM_WINDOWS

#include <cfl/cfl_list.h>

#define FLB_FILE_GLOB_ABORT_ON_ERROR   (((uint64_t) 1) << 0)
#define FLB_FILE_GLOB_MARK_DIRECTORIES (((uint64_t) 1) << 1)
#define FLB_FILE_GLOB_DO_NOT_SORT      (((uint64_t) 1) << 2)
#define FLB_FILE_GLOB_EXPAND_TILDE     (((uint64_t) 1) << 3)

#define FLB_FILE_GLOB_ERROR_SUCCESS          0
#define FLB_FILE_GLOB_ERROR_ABORTED          1
#define FLB_FILE_GLOB_ERROR_NO_MEMORY        2
#define FLB_FILE_GLOB_ERROR_NO_FILE          3
#define FLB_FILE_GLOB_ERROR_NO_ACCESS        4
#define FLB_FILE_GLOB_ERROR_NO_MATCHES       5
#define FLB_FILE_GLOB_ERROR_NO_MORE_RESULTS  6
#define FLB_FILE_GLOB_ERROR_OVERSIZED_PATH   7
#define FLB_FILE_GLOB_ERROR_INVALID_ARGUMENT 8

#ifndef GLOB_NOSPACE
#define GLOB_NOSPACE FLB_FILE_GLOB_ERROR_NO_MEMORY
#endif

#ifndef GLOB_ABORTED
#define GLOB_ABORTED FLB_FILE_GLOB_ERROR_ABORTED
#endif

#ifndef GLOB_NOMATCH
#define GLOB_NOMATCH FLB_FILE_GLOB_ERROR_NO_MATCHES
#endif

#ifndef GLOB_ERR
#define GLOB_ERR FLB_FILE_GLOB_ABORT_ON_ERROR
#endif

#define FLB_FILE_MAX_PATH_LENGTH PATH_MAX

struct flb_file_glob_inner_entry {
    char           *path;
    struct cfl_list _head;
};

struct flb_file_glob_inner_context {
    struct flb_file_glob_inner_entry *current_entry;
    struct cfl_list                   results;
    size_t                            entries;
    size_t                            index;
    uint64_t                          flags;
};

struct flb_file_glob_context {
    struct flb_file_glob_inner_context *inner_context;
    uint64_t                            flags;
    char                               *path;
};

typedef struct {
    struct flb_file_glob_context inner_context;
    char                       **gl_pathv;
    size_t                       gl_pathc;
} glob_t;

int glob(const char *path, uint64_t flags, void *unused, glob_t *context);
void globfree(glob_t *context);
int is_directory(char *path, struct stat *fs_entry_metadata);


#endif /* FLB_SYSTEM_WINDOWS */
#endif /* FLB_GLOB_WIN32_H */