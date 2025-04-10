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

#ifndef FLB_OUT_AZURE_KUSTO_STORE_H
#define FLB_OUT_AZURE_KUSTO_STORE_H


#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_fstore.h>
#include "azure_kusto.h"

struct azure_kusto_file {
    int locked;                      /* locked chunk is busy, cannot write to it */
    int failures;                    /* delivery failures */
    size_t size;                     /* file size */
    time_t create_time;              /* creation time */
    flb_sds_t file_path;             /* file path */
    int lock_fd;                     /* File descriptor for locking */
    struct flb_fstore_file *fsf;     /* reference to parent flb_fstore_file */
};

int azure_kusto_store_buffer_put(struct flb_azure_kusto *ctx, struct azure_kusto_file *azure_kusto_file,
                                 flb_sds_t tag, size_t tag_len,
                                 flb_sds_t data, size_t bytes);

int azure_kusto_store_init(struct flb_azure_kusto *ctx);
int azure_kusto_store_exit(struct flb_azure_kusto *ctx);

int azure_kusto_store_has_data(struct flb_azure_kusto *ctx);
int azure_kusto_store_has_uploads(struct flb_azure_kusto *ctx);

int azure_kusto_store_file_inactive(struct flb_azure_kusto *ctx, struct azure_kusto_file *azure_kusto_file);
struct azure_kusto_file *azure_kusto_store_file_get(struct flb_azure_kusto *ctx, const char *tag,
                                                    int tag_len);
int azure_kusto_store_file_cleanup(struct flb_azure_kusto *ctx, struct azure_kusto_file *azure_kusto_file);
int azure_kusto_store_file_delete(struct flb_azure_kusto *ctx, struct azure_kusto_file *azure_kusto_file);
int azure_kusto_store_file_upload_read(struct flb_azure_kusto *ctx, struct flb_fstore_file *fsf,
                                       char **out_buf, size_t *out_size);

int azure_kusto_store_file_meta_get(struct flb_azure_kusto *ctx, struct flb_fstore_file *fsf);

void azure_kusto_store_file_lock(struct azure_kusto_file *azure_kusto_file);
void azure_kusto_store_file_unlock(struct azure_kusto_file *azure_kusto_file);

#endif
