/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#ifndef FLB_GCS_STORE_H
#define FLB_GCS_STORE_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_fstore.h>

struct gcs_file {
    int locked;                      /* locked chunk is busy, cannot write to it */
    int failures;                    /* delivery failures */
    size_t size;                     /* file size */
    time_t create_time;              /* creation time */
    flb_sds_t file_path;             /* file path */
    struct flb_fstore_file *fsf;     /* reference to parent flb_fstore_file */
};

int gcs_store_buffer_put(struct flb_gcs *ctx, struct gcs_file *gcs_file,
                        const char *tag, int tag_len,
                        char *data, size_t bytes);

int gcs_store_init(struct flb_gcs *ctx);
int gcs_store_exit(struct flb_gcs *ctx);

int gcs_store_has_data(struct flb_gcs *ctx);

int gcs_store_file_inactive(struct flb_gcs *ctx, struct gcs_file *gcs_file);
struct gcs_file *gcs_store_file_get(struct flb_gcs *ctx, const char *tag,
                                  int tag_len);
int gcs_store_file_delete(struct flb_gcs *ctx, struct gcs_file *gcs_file);
int gcs_store_file_read(struct flb_gcs *ctx, struct gcs_file *gcs_file,
                       char **out_buf, size_t *out_size);
int gcs_store_file_upload_read(struct flb_gcs *ctx, struct flb_fstore_file *fsf,
                              char **out_buf, size_t *out_size);

int gcs_store_file_upload_put(struct flb_gcs *ctx,
                             struct flb_fstore_file *fsf, flb_sds_t key,
                             flb_sds_t data);
int gcs_store_file_upload_delete(struct flb_gcs *ctx, struct flb_fstore_file *fsf);

int gcs_store_file_meta_get(struct flb_gcs *ctx, struct flb_fstore_file *fsf);

void gcs_store_file_lock(struct gcs_file *gcs_file);
void gcs_store_file_unlock(struct gcs_file *gcs_file);

#endif
