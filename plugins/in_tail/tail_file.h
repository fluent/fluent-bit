/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#ifndef FLB_TAIL_FILE_H
#define FLB_TAIL_FILE_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fluent-bit/flb_input.h>

#include "tail.h"
#include "tail_fs.h"
#include "tail_config.h"
#include "tail_file_internal.h"

#ifdef FLB_HAVE_REGEX
#define FLB_HASH_TABLE_SIZE 50
#endif

static inline int flb_tail_file_name_cmp(char *name,
                                        struct flb_tail_file *file)
{
#ifdef __linux__
    return strcmp(name, file->name);
#else
    return strcmp(name, file->real_name);
#endif
}

int flb_tail_file_name_dup(char *path, struct flb_tail_file *file);
int flb_tail_file_to_event(struct flb_tail_file *file);
int flb_tail_file_chunk(struct flb_tail_file *file);
int flb_tail_file_append(char *path, struct stat *st, int mode,
                         struct flb_tail_config *ctx);
int flb_tail_file_exists(char *f, struct flb_tail_config *ctx);
void flb_tail_file_remove(struct flb_tail_file *file);
int flb_tail_file_remove_all(struct flb_tail_config *ctx);
char *flb_tail_file_name(struct flb_tail_file *file);
int flb_tail_file_rotated(struct flb_tail_file *file);
int flb_tail_file_rotated_purge(struct flb_input_instance *i_ins,
                                struct flb_config *config, void *context);
int flb_tail_pack_line_map(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                           struct flb_time *time, char **data,
                           size_t *data_size, struct flb_tail_file *file);
int flb_tail_file_pack_line(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                            struct flb_time *time, char *data, size_t data_size,
                            struct flb_tail_file *file);

#endif
