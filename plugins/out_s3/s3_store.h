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

#ifndef FLB_S3_STORE_H
#define FLB_S3_STORE_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_fstore.h>

struct s3_file {
    int locked;                      /* locked chunk is busy, cannot write to it */
    int failures;                    /* delivery failures */
    size_t size;                     /* file size */
    time_t create_time;              /* creation time */
    flb_sds_t file_path;             /* file path */
    struct flb_fstore_file *fsf;   /* reference to parent flb_fstore_file */
};

int s3_store_buffer_put(struct flb_s3 *ctx, struct s3_file *s3_file,
                        const char *tag, int tag_len,
                        char *data, size_t bytes);

int s3_store_init(struct flb_s3 *ctx);
int s3_store_exit(struct flb_s3 *ctx);

int s3_store_has_data(struct flb_s3 *ctx);
int s3_store_file_inactive(struct flb_s3 *ctx, struct s3_file *s3_file);
struct s3_file *s3_store_file_get(struct flb_s3 *ctx, const char *tag,
                                  int tag_len);
int s3_store_file_delete(struct flb_s3 *ctx, struct s3_file *s3_file);
int s3_store_file_read(struct flb_s3 *ctx, struct s3_file *s3_file,
                       char **out_buf, size_t *out_size);

void s3_store_file_lock(struct s3_file *s3_file);
void s3_store_file_unlock(struct s3_file *s3_file);

#endif
