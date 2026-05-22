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
#include <sys/stat.h>
#include <fcntl.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <fluent-bit/flb_file_win32.h>
#else
#include <fluent-bit/flb_file_unix.h>
#endif

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

struct flb_file_glob_inner_context;

struct flb_file_glob_context {
   struct flb_file_glob_inner_context *inner_context;
   uint64_t                            flags;
   char                               *path;
};

struct flb_file_stat {
   uint64_t  device;
   uint64_t  inode;
   uint16_t  mode;
   int64_t   modification_time;
   int16_t   hard_link_count;
   int64_t   size;
};

int flb_file_glob_start(struct flb_file_glob_context *context,
                        const char *path,
                        uint64_t flags);

void flb_file_glob_clean(struct flb_file_glob_context *context);

int flb_file_glob_fetch(struct flb_file_glob_context *context,
                        char **result);

flb_file_handle flb_file_open(const char *path,
                              unsigned int flags);

void flb_file_close(flb_file_handle handle);

ssize_t flb_file_read(flb_file_handle handle,
                      void *output_buffer,
                      size_t byte_count);

int64_t flb_file_lseek(flb_file_handle handle,
                       int64_t offset,
                       int reference_point);

int flb_file_stat(const char *path,
                  struct flb_file_stat *output_buffer);

int flb_file_lstat(const char *path,
                   struct flb_file_stat *output_buffer);

int flb_file_fstat(flb_file_handle handle,
                   struct flb_file_stat *output_buffer);

char *flb_file_get_path(flb_file_handle handle);

char *flb_file_basename(const char *path);

flb_sds_t flb_file_read_contents(const char *path);
#endif
