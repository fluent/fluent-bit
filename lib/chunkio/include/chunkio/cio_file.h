/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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

#ifndef CIO_FILE_H
#define CIO_FILE_H

#include <chunkio/cio_chunk.h>
#include <chunkio/cio_file_st.h>
#include <chunkio/cio_crc32.h>

/* Linux fallocate() strategy */
#define CIO_FILE_LINUX_FALLOCATE        0
#define CIO_FILE_LINUX_POSIX_FALLOCATE  1

struct cio_file {
    int fd;                   /* file descriptor      */
    int flags;                /* open flags */
    int synced;               /* sync after latest write ? */
    int allocate_strategy;    /* linux-only: fallocate strategy */
    size_t fs_size;           /* original size in the file system */
    size_t data_size;         /* number of bytes used */
    size_t page_size;         /* curent page size */
    size_t alloc_size;        /* allocated size       */
    size_t realloc_size;      /* chunk size to increase alloc */
    char *path;               /* root path + stream   */
    char *map;                /* map of data          */
    struct cio_ctx *ctx;      /* owning context */
#ifdef _WIN32
    HANDLE backing_file;
    HANDLE backing_mapping;
#endif
    int taint_flag;           /* content modification flag */
    /* cached addr */
    char *st_content;
    crc_t crc_cur;            /* crc: current value calculated */
    int crc_reset;            /* crc: must recalculate from the beginning ? */
    int auto_remap_warned;    /* has sync auto-remap warning been emitted? */
    int map_truncated_warned; /* has RO truncation warning been emitted? */
};

size_t cio_file_real_size(struct cio_file *cf);
struct cio_file *cio_file_open(struct cio_ctx *ctx,
                               struct cio_stream *st,
                               struct cio_chunk *ch,
                               int flags,
                               size_t size,
                               int *err);
void cio_file_close(struct cio_chunk *ch, int delete);
int cio_file_delete(struct cio_ctx *ctx, struct cio_stream *st, const char *name);
int cio_file_write(struct cio_chunk *ch, const void *buf, size_t count);
int cio_file_write_metadata(struct cio_chunk *ch, char *buf, size_t size);
int cio_file_sync(struct cio_chunk *ch);
int cio_file_resize(struct cio_file *cf, size_t new_size);
char *cio_file_hash(struct cio_file *cf);
void cio_file_hash_print(struct cio_file *cf);
void cio_file_calculate_checksum(struct cio_file *cf, crc_t *out);
void cio_file_scan_dump(struct cio_ctx *ctx, struct cio_stream *st);
int cio_file_read_prepare(struct cio_ctx *ctx, struct cio_chunk *ch);
int cio_file_content_copy(struct cio_chunk *ch,
                          void **out_buf, size_t *out_size);


int cio_file_is_up(struct cio_chunk *ch, struct cio_file *cf);
int cio_file_down(struct cio_chunk *ch);
int cio_file_up(struct cio_chunk *ch);
int cio_file_up_force(struct cio_chunk *ch);
int cio_file_lookup_user(char *user, void **result);
int cio_file_lookup_group(char *group, void **result);
int cio_file_update_size(struct cio_file *cf);

#define cio_file_report_runtime_error() { cio_file_native_report_runtime_error(); }
#define cio_file_report_os_error() { cio_file_native_report_os_error(); }

#endif
