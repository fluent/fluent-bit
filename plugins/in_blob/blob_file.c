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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_input_blob.h>

#include <fcntl.h>
#include <sys/stat.h>

#include "blob.h"
#include "blob_db.h"

int blob_file_append(struct blob_ctx *ctx, char *path, struct stat *st)
{
    int fd;
    int ret;
    uint64_t id_found;
    struct cfl_list *head;
    struct blob_file *bfile;
    struct flb_input_instance *ins = ctx->ins;

    /* check if the file already exists in the linked list in memory */
    cfl_list_foreach(head, &ctx->files) {
        bfile = cfl_list_entry(head, struct blob_file, _head);
        if (strcmp(bfile->path, path) == 0) {
            /* file already exists */
            return 1;
        }
    }

#ifdef FLB_HAVE_SQLDB
    if (ctx->database_file) {
        /* the file was already registered, just skipt it */
        if (blob_db_file_exists(ctx, path, &id_found) == FLB_TRUE) {
            return 1;
        }
    }
#endif

    /* try to open the file */
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open %s", path);
        return -1;
    }
    close(fd);

    /* create the reference entry */
    bfile = flb_calloc(1, sizeof(struct blob_file));
    if (!bfile) {
        flb_errno();
        return -1;
    }

    bfile->path = cfl_sds_create(path);
    if (!bfile->path) {
        flb_free(bfile);
        return -1;
    }
    bfile->size = st->st_size;

#ifdef FLB_HAVE_SQLDB
    /* insert the entry into the database */
    if (ctx->database_file) {
        bfile->db_id = blob_db_file_insert(ctx, path, st->st_size);
        if (bfile->db_id < 0) {
            cfl_sds_destroy(bfile->path);
            flb_free(bfile);
            return -1;
        }
    }
#endif

    ret = flb_input_blob_file_register(ctx->ins, ctx->log_encoder,
                                       ins->tag, ins->tag_len,
                                       bfile->path, bfile->size);
    if (ret == -1) {
        cfl_sds_destroy(bfile->path);
        flb_free(bfile);
        return -1;
    }

    cfl_list_add(&bfile->_head, &ctx->files);
    return 0;
}

/* release resources of a blob_file */
void blob_file_list_remove(struct blob_file *bfile)
{
    if (bfile->path) {
        cfl_sds_destroy(bfile->path);
    }
    flb_free(bfile);
}

/* release all blob_files from the context list */
void blob_file_list_remove_all(struct blob_ctx *ctx)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct blob_file *bfile;

    cfl_list_foreach_safe(head, tmp, &ctx->files) {
        bfile = cfl_list_entry(head, struct blob_file, _head);
        cfl_list_del(&bfile->_head);
        blob_file_list_remove(bfile);
    }
}