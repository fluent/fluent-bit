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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <limits.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_crc32.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_st.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>

char cio_file_init_bytes[] =   {
    /* file type (2 bytes)    */
    CIO_FILE_ID_00, CIO_FILE_ID_01,

    /* crc32 (4 bytes) in network byte order */
    0xff, 0x12, 0xd9, 0x41,

    /* padding bytes (we have 16 extra bytes */
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,

    /* metadata length (2 bytes) */
    0x00, 0x00
};

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

/* Get the number of bytes in the Content section */
static size_t content_len(struct cio_file *cf)
{
    int meta;
    size_t len;

    meta = cio_file_st_get_meta_len(cf->map);
    len = 2 + meta + cf->data_size;
    return len;
}

/* Calculate content checksum in a variable */
void cio_file_calculate_checksum(struct cio_file *cf, crc_t *out)
{
    crc_t val;
    size_t len;
    unsigned char *in_data;

    len = content_len(cf);
    in_data = (unsigned char *) cf->map + CIO_FILE_CONTENT_OFFSET;

    val = cio_crc32_update(cf->crc_cur, in_data, len);
    *out = val;
}

/* Update crc32 checksum into the memory map */
static void update_checksum(struct cio_file *cf,
                            unsigned char *data, size_t len)
{
    crc_t crc;

    crc = cio_crc32_update(cf->crc_cur, data, len);
    memcpy(cf->map + 2, &crc, sizeof(crc));
    cf->crc_cur = crc;
}

/* Finalize CRC32 context and update the memory map */
static void finalize_checksum(struct cio_file *cf)
{
    crc_t crc;

    crc = cio_crc32_finalize(cf->crc_cur);
    crc = htonl(crc);
    memcpy(cf->map + 2, &crc, sizeof(crc));
}

static void write_init_header(struct cio_file *cf)
{
    memcpy(cf->map, cio_file_init_bytes, sizeof(cio_file_init_bytes));
}

/* Return the available size in the file map to write data */
static size_t get_available_size(struct cio_file *cf)
{
    size_t av;
    int map_len;

    map_len = cio_file_st_get_meta_len(cf->map);

    av = cf->alloc_size - cf->data_size;
    av -= (CIO_FILE_HEADER_MIN + map_len);

    return av;
}

/*
 * For the recently opened or created file, check the structure format
 * and validate relevant fields.
 */
static int cio_file_format_check(struct cio_chunk *ch,
                                 struct cio_file *cf, int flags)
{
    char *p;
    crc_t crc_check;
    crc_t crc;

    p = cf->map;

    /* If the file is empty, put the structure on it */
    if (cf->fs_size == 0) {
        /* check we have write permissions */
        if ((cf->flags & CIO_OPEN) == 0) {
            cio_log_warn(ch->ctx,
                         "[cio file] cannot initialize chunk (read-only)");
            return -1;
        }

        /* at least we need 24 bytes as allocated space */
        if (cf->alloc_size < CIO_FILE_HEADER_MIN) {
            cio_log_warn(ch->ctx, "[cio file] cannot initialize chunk");
            return -1;
        }

        /* Initialize init bytes */
        write_init_header(cf);

        /* Write checksum in context (note: crc32 not finalized) */
        cio_file_calculate_checksum(cf, &cf->crc_cur);
    }
    else {
        /* Check first two bytes */
        if (p[0] != CIO_FILE_ID_00 || p[1] != CIO_FILE_ID_01) {
            cio_log_debug(ch->ctx, "[cio file] invalid header at %s",
                          ch->name);
            return -1;
        }

        /* Get hash stored in the mmap */
        p = cio_file_st_get_hash(cf->map);

        /* Calculate data checksum in variable */
        cio_file_calculate_checksum(cf, &crc);

        /* Compare checksum */
        if (ch->ctx->flags & CIO_CHECKSUM) {
            crc_check = cio_crc32_finalize(crc);
            crc_check = htonl(crc_check);
            if (memcmp(p, &crc_check, sizeof(crc_check)) != 0) {
                cio_log_debug(ch->ctx, "[cio file] invalid crc32 at %s",
                              ch->name);
                return -1;
            }
            cf->crc_cur = crc;
        }
    }

    return 0;
}

/*
 * Open or create a data file: the following behavior is expected depending
 * of the passed flags:
 *
 * CIO_OPEN:
 *    - Open for read/write, if the file don't exist, it's created and the
 *      memory map size is assigned to the given value on 'size'.
 *
 * CIO_OPEN_RD:
 *    - If file exisst, open it in read-only mode.
 */
struct cio_file *cio_file_open(struct cio_ctx *ctx,
                               struct cio_stream *st,
                               struct cio_chunk *ch,
                               int flags,
                               size_t size)
{
    int psize;
    int ret;
    int len;
    int oflags;
    size_t fs_size = 0;
    ssize_t content_size;
    char *path;
    struct cio_file *cf;
    struct stat fst;
    (void) ctx;

    len = strlen(ch->name);
    if (len == 1 && (ch->name[0] == '.' || ch->name[0] == '/')) {
        cio_log_error(ctx, "[cio file] invalid file name");
        return NULL;
    }

    /* Compose path for the file */
    psize = strlen(ctx->root_path) + strlen(st->name) + strlen(ch->name);
    psize += 8;

    path = malloc(psize);
    if (!path) {
        cio_errno();
        return NULL;
    }

    ret = snprintf(path, psize, "%s/%s/%s",
                   ctx->root_path, st->name, ch->name);
    if (ret == -1) {
        cio_errno();
        free(path);
        return NULL;
    }

    /* Create file context */
    cf = calloc(1, sizeof(struct cio_file));
    if (!cf) {
        cio_errno();
        free(path);
        return NULL;
    }
    cf->flags = flags;
    cf->realloc_size = getpagesize() * 8;
    cf->st_content = NULL;
    cf->crc_cur = cio_crc32_init();
    cf->path = path;

    /* Open file descriptor */
    if (flags & CIO_OPEN) {
        cf->fd = open(path, O_RDWR | O_CREAT, (mode_t) 0600);
    }
    else if (flags & CIO_OPEN_RD) {
        cf->fd = open(path, O_RDONLY);
    }

    if (cf->fd == -1) {
        cio_errno();
        cio_log_error(ctx, "cannot open/create %s", path);
        cio_file_close(ch, CIO_FALSE);
        return NULL;
    }

    /* Check if some previous content exists */
    ret = fstat(cf->fd, &fst);
    if (ret == -1) {
        cio_errno();
        cio_file_close(ch, CIO_FALSE);
        return NULL;
    }

    /* Get file size from the file system */
    fs_size = fst.st_size;

    /* Mmap */
    if (flags & CIO_OPEN) {
        oflags = PROT_READ | PROT_WRITE;
    }
    else if (flags & CIO_OPEN_RD) {
        oflags = PROT_READ;
    }

    /* If the file is not empty, use file size for the memory map */
    if (fs_size > 0) {
        size = fs_size;
        cf->synced = CIO_TRUE;
    }
    else if (fs_size == 0) {
        cf->synced = CIO_FALSE;

        /* Adjust size to make room for headers */
        if (size < CIO_FILE_HEADER_MIN) {
            size += CIO_FILE_HEADER_MIN;
        }

        /* For empty files, make room in the file system */
        size = ROUND_UP(size, cio_page_size);
        ret = cio_file_fs_size_change(cf, size);
        if (ret == -1) {
            cio_errno();
            cio_file_close(ch, CIO_TRUE);
            return NULL;
        }
    }

    /* Map the file */
    size = ROUND_UP(size, cio_page_size);
    cf->map = mmap(0, size, oflags, MAP_SHARED, cf->fd, 0);
    if (cf->map == MAP_FAILED) {
        cio_errno();
        cf->map = NULL;
        cio_file_close(ch, CIO_TRUE);
        return NULL;
    }
    cf->alloc_size = size;

    /* check content data size */
    if (fs_size > 0) {
        content_size = cio_file_st_get_content_size(cf->map, fs_size);
        if (content_size == -1) {
            cio_log_error(ctx, "invalid content size %s", path);
            cio_file_close(ch, CIO_TRUE);
            return NULL;
        }
        cf->data_size = content_size;
        cf->fs_size = fs_size;
    }
    else {
        cf->data_size = 0;
        cf->fs_size = 0;
    }

    cio_file_format_check(ch, cf, flags);
    cf->st_content = cio_file_st_get_content(cf->map);
    cio_log_debug(ctx, "%s:%s mapped OK", st->name, ch->name);

    return cf;
}

void cio_file_close(struct cio_chunk *ch, int delete)
{
    int ret;
    struct cio_file *cf = (struct cio_file *) ch->backend;

    /* check if the file needs to be synchronized */
    if (cf->synced == CIO_FALSE && cf->map) {
        ret = cio_file_sync(ch);
        if (ret == -1) {
            cio_log_error(ch->ctx,
                          "[cio file] error doing file sync on close at "
                          "%s:%s", ch->st->name, ch->name);
        }
    }

    /* unmap file */
    if (cf->map) {
        munmap(cf->map, cf->alloc_size);
    }
    close(cf->fd);

    if (delete == CIO_TRUE) {
        ret = unlink(cf->path);
        if (ret == -1) {
            cio_errno();
            cio_log_error(ch->ctx,
                          "[cio file] error deleting file at close %s:%s",
                          ch->st->name, ch->name);
        }
    }

    free(cf->path);
    free(cf);
}

int cio_file_write(struct cio_chunk *ch, const void *buf, size_t count)
{
    int ret;
    void *tmp;
    size_t av_size;
    size_t new_size;
    struct cio_file *cf = (struct cio_file *) ch->backend;

    if (count == 0) {
        /* do nothing */
        return 0;
    }

    /* get available size */
    av_size = get_available_size(cf);

    /* validate there is enough space, otherwise resize */
    if (count > av_size) {
        if (av_size + cf->realloc_size < count) {
            new_size = cf->alloc_size + count;
            cio_log_debug(ch->ctx,
                          "[cio file] realloc size is not big enough "
                          "for incoming data, consider to increase it");
        }
        else {
            new_size = cf->alloc_size + cf->realloc_size;
        }

        new_size = ROUND_UP(new_size, cio_page_size);
        ret = cio_file_fs_size_change(cf, new_size);
        if (ret == -1) {
            cio_errno();
            cio_log_error(ch->ctx,
                          "[cio_file] error setting new file size on write");
            return -1;
        }
        /* OSX mman does not implement mremap or MREMAP_MAYMOVE. */
#ifndef MREMAP_MAYMOVE
        if (munmap(cf->data_size, av_size) == -1)
            return -1;
        tmp = mmap(0, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, cf->fd, 0);
#else
        tmp = mremap(cf->map, cf->alloc_size,
                     new_size, MREMAP_MAYMOVE);
#endif
        if (tmp == MAP_FAILED) {
            cio_errno();
            cio_log_error(ch->ctx,
                          "[cio file] data exceeds available space "
                          "(alloc=%lu current_size=%lu write_size=%lu)",
                          cf->alloc_size, cf->data_size, count);
            return -1;
        }

        cio_log_debug(ch->ctx,
                      "[cio file] alloc_size from %lu to %lu",
                      cf->alloc_size, new_size);

        cf->map = tmp;
        cf->alloc_size = new_size;
    }

    if (ch->ctx->flags & CIO_CHECKSUM) {
        update_checksum(cf, (unsigned char *) buf, count);
    }

    cf->st_content = cio_file_st_get_content(cf->map);
    memcpy(cf->st_content + cf->data_size, buf, count);

    cf->data_size += count;
    cf->synced = CIO_FALSE;

    return 0;
}

int cio_file_sync(struct cio_chunk *ch)
{
    int ret;
    int sync_mode;
    size_t av_size;
    size_t size;
    struct stat fst;
    struct cio_file *cf = (struct cio_file *) ch->backend;

    if (cf->flags & CIO_OPEN_RD) {
        return 0;
    }

    if (cf->synced == CIO_TRUE) {
        return 0;
    }

    ret = fstat(cf->fd, &fst);
    if (ret == -1) {
        cio_errno();
        return -1;
    }

    /* If there are extra space, truncate the file size */
    av_size = get_available_size(cf);
    if (av_size > 0) {
        size = cf->alloc_size - av_size;
        ret = cio_file_fs_size_change(cf, size);
        if (ret == -1) {
            cio_errno();
            cio_log_error(ch->ctx,
                          "[cio file sync] error adjusting size at: "
                          " %s/%s", ch->st->name, ch->name);
        }
        cf->alloc_size = size;
    }
    else if (cf->alloc_size > fst.st_size) {
        ret = cio_file_fs_size_change(cf, cf->alloc_size);
        if (ret == -1) {
            cio_errno();
            cio_log_error(ch->ctx,
                          "[cio file sync] error adjusting size at: "
                          " %s/%s", ch->st->name, ch->name);
        }
    }

    /* Finalize CRC32 checksum */
    if (ch->ctx->flags & CIO_CHECKSUM) {
        finalize_checksum(cf);
    }

    /* Sync mode */
    if (ch->ctx->flags & CIO_FULL_SYNC) {
        sync_mode = MS_SYNC;
    }
    else {
        sync_mode = MS_ASYNC;
    }

    /* Commit changes to disk */
    ret = msync(cf->map, cf->alloc_size, sync_mode);
    if (ret == -1) {
        cio_errno();
        return -1;
    }

    cf->synced = CIO_TRUE;
    cio_log_debug(ch->ctx, "[cio file] synced at: %s/%s",
                  ch->st->name, ch->name);
    return 0;
}

/* Change the size of file in the file system (not memory map) */
int cio_file_fs_size_change(struct cio_file *cf, size_t new_size)
{
    int ret;

    if (new_size == cf->alloc_size) {
        return 0;
    }

    /* macOS does not have fallocate().
     * So, we should use ftruncate always. */
#ifndef __APPLE__
    if (new_size > cf->alloc_size) {
        /*
         * To increase the file size we use fallocate() since this option
         * will send a proper ENOSPC error if the file system ran out of
         * space. ftruncate() will not fail and upon memcpy() over the
         * mmap area it will trigger a 'Bus Error' crashing the program.
         *
         * fallocate() is not portable, Linux only.
         */
        ret = fallocate(cf->fd, 0, 0, new_size);
    }
    else
#endif
    {
        ret = ftruncate(cf->fd, new_size);
    }

    return ret;
}

char *cio_file_hash(struct cio_file *cf)
{
    return (cf->map + 2);
}

void cio_file_hash_print(struct cio_file *cf)
{
    printf("crc cur=%lu\n", cf->crc_cur);
    printf("%08lx\n", (long unsigned int ) cf->crc_cur);
}

/* Dump files from given stream */
void cio_file_scan_dump(struct cio_ctx *ctx, struct cio_stream *st)
{
    int meta_len;
    char *p;
    crc_t crc;
    crc_t crc_fs;
    char tmp[PATH_MAX];
    struct mk_list *head;
    struct cio_chunk *ch;
    struct cio_file *cf;

    mk_list_foreach(head, &st->files) {
        ch = mk_list_entry(head, struct cio_chunk, _head);
        cf = ch->backend;

        snprintf(tmp, sizeof(tmp) -1, "%s/%s", st->name, ch->name);

        meta_len = cio_file_st_get_meta_len(cf->map);

        p = cio_file_st_get_hash(cf->map);

        memcpy(&crc_fs, p, sizeof(crc_fs));
        crc_fs = ntohl(crc_fs);

        printf("        %-60s", tmp);

        /*
         * the crc32 specified in the file is stored in 'val' now, if
         * checksum mode is enabled we have to verify it.
         */
        if (ctx->flags & CIO_CHECKSUM) {
            cio_file_calculate_checksum(cf, &crc);

            /*
             * finalize the checksum and compare it value using the
             * host byte order.
             */
            crc = cio_crc32_finalize(crc);
            if (crc != crc_fs) {
                printf("checksum error=%08x expected=%08x, ",
                       (uint32_t) crc_fs, (uint32_t) crc);
            }
        }
        printf("meta_len=%d, data_size=%lu, crc=%08x\n",
               meta_len, cf->data_size, (uint32_t) crc_fs);
    }
}
