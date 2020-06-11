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

#ifndef FLB_TAIL_FILE_H
#define FLB_TAIL_FILE_H

#include <sys/types.h>
#include <sys/stat.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_input.h>

#include "tail.h"
#include "tail_fs.h"
#include "tail_config.h"
#include "tail_file_internal.h"

#ifdef FLB_SYSTEM_WINDOWS
#include "win32.h"
#endif

#ifdef FLB_HAVE_REGEX
#define FLB_HASH_TABLE_SIZE 50
#endif

static inline int flb_tail_target_file_name_cmp(char *name,
                                                struct flb_tail_file *file)
{
    int ret;
    char *name_a = NULL;
    char *name_b = NULL;
    char *base_a = NULL;
    char *base_b = NULL;

    name_a = flb_strdup(name);
    if (!name_a) {
        flb_errno();
        ret = -1;
        goto out;
    }

    base_a = flb_strdup(basename(name_a));
    if (!base_a) {
        flb_errno();
        ret = -1;
        goto out;
    }

#if defined(FLB_SYSTEM_WINDOWS)
    name_b = flb_strdup(file->real_name);
    if (!name_b) {
        flb_errno();
        ret = -1;
        goto out;
    }

    base_b = basename(name_b);
    ret = _stricmp(base_a, base_b);
#else
    name_b = flb_strdup(file->real_name);
    if (!name_b) {
        flb_errno();
        ret = -1;
        goto out;
    }
    base_b = basename(name_b);
    ret = strcmp(base_a, base_b);
#endif

 out:
    flb_free(name_a);
    flb_free(name_b);
    flb_free(base_a);

    /* FYI: 'base_b' never points to a new allocation, no flb_free is needed */

    return ret;
}

int flb_tail_file_name_dup(char *path, struct flb_tail_file *file);
int flb_tail_file_to_event(struct flb_tail_file *file);
int flb_tail_file_chunk(struct flb_tail_file *file);
int flb_tail_file_append(char *path, struct stat *st, int mode,
                         struct flb_tail_config *ctx);
void flb_tail_file_remove(struct flb_tail_file *file);
int flb_tail_file_remove_all(struct flb_tail_config *ctx);
char *flb_tail_file_name(struct flb_tail_file *file);
int flb_tail_file_is_rotated(struct flb_tail_config *ctx,
                             struct flb_tail_file *file);
int flb_tail_file_rotated(struct flb_tail_file *file);
int flb_tail_file_purge(struct flb_input_instance *ins,
                        struct flb_config *config, void *context);
int flb_tail_pack_line_map(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                           struct flb_time *time, char **data,
                           size_t *data_size, struct flb_tail_file *file);
int flb_tail_file_pack_line(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                            struct flb_time *time, char *data, size_t data_size,
                            struct flb_tail_file *file);

#endif
