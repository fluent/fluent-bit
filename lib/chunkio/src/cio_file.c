/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018-2019 Eduardo Silva <eduardo@monkey.io>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

#include <chunkio/chunkio.h>
#include <chunkio/chunkio_compat.h>
#include <chunkio/cio_crc32.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_native.h>
#include <chunkio/cio_file_st.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_error.h>
#include <chunkio/cio_utils.h>

size_t scio_file_page_size = 0;

char cio_file_init_bytes[] =   {
    /* file type (2 bytes)    */
    CIO_FILE_ID_00, CIO_FILE_ID_01,

    /* crc32 (4 bytes) in network byte order */
    0xff, 0x12, 0xd9, 0x41,

    /* padding bytes (we have 16 extra bytes) */
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,

    /* metadata length (2 bytes) */
    0x00, 0x00
};

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))


/* Calculate content checksum in a variable */
void cio_file_calculate_checksum(struct cio_file *cf, crc_t *out)
{
    crc_t val;
    size_t len;
    ssize_t content_length;
    unsigned char *in_data;

    if (cf->fs_size == 0) {
        cio_file_update_size(cf);
    }

    /* Metadata length header + metadata length + content length */
    len  = 2;
    len += cio_file_st_get_meta_len(cf->map);

    content_length = cio_file_st_get_content_len(cf->map,
                                                 cf->fs_size,
                                                 cf->page_size,
                                                 cf->taint_flag);

    if (content_length > 0) {
        len += content_length;
    }

    in_data = (unsigned char *) cf->map + CIO_FILE_CONTENT_OFFSET;

    val = cio_crc32_update(cf->crc_cur, in_data, len);
    *out = val;
}

/* Update crc32 checksum into the memory map */
static void update_checksum(struct cio_file *cf,
                            unsigned char *data, size_t len)
{
    crc_t crc;
    crc_t tmp;

    if (cf->crc_reset) {
        cf->crc_cur = cio_crc32_init();
        cio_file_calculate_checksum(cf, &tmp);
        cf->crc_cur = tmp;
        cf->crc_reset = CIO_FALSE;
    }

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

/*
 * adjust_layout: if metadata has changed, we need to adjust the content
 * data and reference pointers.
 */
static int adjust_layout(struct cio_chunk *ch,
                         struct cio_file *cf, size_t meta_size)
{
    cio_file_st_set_meta_len(cf->map, (uint16_t) meta_size);

    /* Update checksum */
    if (ch->ctx->options.flags & CIO_CHECKSUM) {
        /* reset current crc since we are calculating from zero */
        cf->crc_cur = cio_crc32_init();
        cio_file_calculate_checksum(cf, &cf->crc_cur);
    }

    /* Sync changes to disk */
    cf->synced = CIO_FALSE;

    return 0;
}

/* Initialize Chunk header & structure */
static void write_init_header(struct cio_chunk *ch, struct cio_file *cf)
{
    memcpy(cf->map, cio_file_init_bytes, sizeof(cio_file_init_bytes));

    /* If no checksum is enabled, reset the initial crc32 bytes */
    if (!(ch->ctx->options.flags & CIO_CHECKSUM)) {
        cf->map[2] = 0;
        cf->map[3] = 0;
        cf->map[4] = 0;
        cf->map[5] = 0;
    }

    cio_file_st_set_content_len(cf->map, 0);
}

/* Return the available size in the file map to write data */
static size_t get_available_size(struct cio_file *cf, int *meta_len)
{
    size_t av;
    int metadata_len;

    /* Get metadata length */
    metadata_len = cio_file_st_get_meta_len(cf->map);

    av  = cf->alloc_size;
    av -= CIO_FILE_HEADER_MIN;
    av -= metadata_len;
    av -= cf->data_size;

    *meta_len = metadata_len;

    return av;
}

/*
 * For the recently opened or created file, check the structure format
 * and validate relevant fields.
 */
static int cio_file_format_check(struct cio_chunk *ch,
                                 struct cio_file *cf, int flags)
{
    size_t metadata_length;
    ssize_t content_length;
    ssize_t logical_length;
    unsigned char *p;
    crc_t crc_check;
    crc_t crc;

    (void) flags;

    p = (unsigned char *) cf->map;

    /* If the file is empty, put the structure on it */
    if (cf->fs_size == 0) {
        /* check we have write permissions */
        if ((cf->flags & CIO_OPEN) == 0) {
            cio_log_warn(ch->ctx,
                         "[cio file] cannot initialize chunk (read-only)");
            cio_error_set(ch, CIO_ERR_PERMISSION);

            return -1;
        }

        /* at least we need 24 bytes as allocated space */
        if (cf->alloc_size < CIO_FILE_HEADER_MIN) {
            cio_log_warn(ch->ctx, "[cio file] cannot initialize chunk");
            cio_error_set(ch, CIO_ERR_BAD_LAYOUT);

            return -1;
        }

        /* Initialize init bytes */
        write_init_header(ch, cf);

        /* Write checksum in context (note: crc32 not finalized) */
        if (ch->ctx->options.flags & CIO_CHECKSUM) {
            cio_file_calculate_checksum(cf, &cf->crc_cur);
        }
    }
    else {
        /* Check first two bytes */
        if (p[0] != CIO_FILE_ID_00 || p[1] != CIO_FILE_ID_01) {
            cio_log_debug(ch->ctx, "[cio file] invalid header at %s",
                          ch->name);
            cio_error_set(ch, CIO_ERR_BAD_LAYOUT);

            return -1;
        }

        /* Expected / logical file size verification */
        content_length = cio_file_st_get_content_len(cf->map,
                                                     cf->fs_size,
                                                     cf->page_size,
                                                     cf->taint_flag);

        if (content_length == -1) {
            cio_log_debug(ch->ctx, "[cio file] truncated header (%zu / %zu) %s",
                          cf->fs_size, CIO_FILE_HEADER_MIN, ch->name);
            cio_error_set(ch, CIO_ERR_BAD_FILE_SIZE);

            return -1;
        }

        metadata_length = cio_file_st_get_meta_len(cf->map);

        logical_length = CIO_FILE_HEADER_MIN +
                         metadata_length +
                         content_length;

        if (logical_length > cf->fs_size) {
            cio_log_debug(ch->ctx, "[cio file] truncated file (%zd / %zd) %s",
                          cf->fs_size, logical_length, ch->name);
            cio_error_set(ch, CIO_ERR_BAD_FILE_SIZE);

            return -1;
        }

        /* Checksum */
        if (ch->ctx->options.flags & CIO_CHECKSUM) {
            /* Initialize CRC variable */
            cf->crc_cur = cio_crc32_init();

            /* Get checksum stored in the mmap */
            p = (unsigned char *) cio_file_st_get_hash(cf->map);

            /* Calculate content checksum */
            cio_file_calculate_checksum(cf, &crc);

            /* Compare */
            crc_check = cio_crc32_finalize(crc);
            crc_check = htonl(crc_check);

            if (memcmp(p, &crc_check, sizeof(crc_check)) != 0) {
                cio_log_info(ch->ctx, "[cio file] invalid crc32 at %s/%s",
                              ch->name, cf->path);
                cio_error_set(ch, CIO_ERR_BAD_CHECKSUM);

                return -1;
            }

            cf->crc_cur = crc;
        }
    }

    return 0;
}

/*
 * Unmap the memory for the opened file in question. It make sure
 * to sync changes to disk first.
 */
static int munmap_file(struct cio_ctx *ctx, struct cio_chunk *ch)
{
    int ret;
    struct cio_file *cf;

    cf = (struct cio_file *) ch->backend;

    if (!cf) {
        return -1;
    }

    /* File not mapped */
    if (cf->map == NULL) {
        return -1;
    }

    /* Sync pending changes to disk */
    if (cf->synced == CIO_FALSE) {
        ret = cio_file_sync(ch);
        if (ret == -1) {
            cio_log_error(ch->ctx,
                          "[cio file] error syncing file at "
                          "%s:%s", ch->st->name, ch->name);
        }
    }

    /* Unmap file */
    ret = cio_file_native_unmap(cf);
    if (ret != CIO_OK) {
        return -1;
    }

    cf->data_size = 0;
    cf->alloc_size = 0;

    /* Adjust counters */
    cio_chunk_counter_total_up_sub(ctx);

    return 0;
}

/*
 * This function creates the memory map for the open file descriptor plus
 * setup the chunk structure reference.
 */
static int mmap_file(struct cio_ctx *ctx, struct cio_chunk *ch, size_t size)
{
    ssize_t          content_size;
    size_t           fs_size;
    size_t           requested_map_size;
    int              ret;
    struct cio_file *cf;

    cf = (struct cio_file *) ch->backend;

    if (cf->map != NULL) {
        return CIO_OK;
    }

    cf->taint_flag = CIO_FALSE;

    /*
     * 'size' value represents the value of a previous fstat(2) set by a previous
     * caller. If the value is greater than zero, just use it, otherwise do a new
     * fstat(2) of the file descriptor.
     */

    fs_size = 0;

    if (size > 0) {
        fs_size = size;
    }
    else {
        /* Get file size from the file system */
        ret = cio_file_native_get_size(cf, &fs_size);

        if (ret != CIO_OK) {
            cio_file_report_os_error();

            return CIO_ERROR;
        }
    }

    /* If the file is not empty, use file size for the memory map */
    if (fs_size > 0) {
        size = fs_size;
        cf->synced = CIO_TRUE;
    }
    else if (fs_size == 0) {
        /* We can only prepare a file if it has been opened in RW mode */
        if ((cf->flags & CIO_OPEN_RW) == 0) {
            cio_error_set(ch, CIO_ERR_PERMISSION);

            return CIO_CORRUPTED;
        }

        cf->synced = CIO_FALSE;

        /* Adjust size to make room for headers */
        if (size < CIO_FILE_HEADER_MIN) {
            size += CIO_FILE_HEADER_MIN;
        }

        /* For empty files, make room in the file system */
        size = ROUND_UP(size, ctx->page_size);
        ret = cio_file_resize(cf, size);

        if (ret != CIO_OK) {
            cio_log_error(ctx, "cannot adjust chunk size '%s' to %lu bytes",
                          cf->path, size);

            return CIO_ERROR;
        }

        cio_log_debug(ctx, "%s:%s adjusting size OK", ch->st->name, ch->name);
    }

    cf->alloc_size = size;

    /* Map the file */
    requested_map_size = cf->alloc_size;
    ret = cio_file_native_map(cf, cf->alloc_size);

    if (ret != CIO_OK) {
        cio_log_error(ctx, "cannot mmap/read chunk '%s'", cf->path);

        return CIO_ERROR;
    }

    if ((cf->flags & CIO_OPEN_RD) && requested_map_size != cf->alloc_size) {
        if (cf->map_truncated_warned == CIO_FALSE) {
            cio_log_warn(ctx,
                         "[cio file] truncated read-only map from %zu to %zu bytes: %s/%s",
                         requested_map_size,
                         cf->alloc_size,
                         ch->st->name,
                         ch->name);
            cf->map_truncated_warned = CIO_TRUE;
        }
    }
    else {
        cf->map_truncated_warned = CIO_FALSE;
    }

    /* check content data size */
    if (fs_size > 0) {
        content_size = cio_file_st_get_content_len(cf->map,
                                                   fs_size,
                                                   cf->page_size,
                                                   cf->taint_flag);

        if (content_size == -1) {
            cio_error_set(ch, CIO_ERR_BAD_FILE_SIZE);

            cio_log_error(ctx, "invalid content size %s", cf->path);

            cio_file_native_unmap(cf);

            cf->data_size = 0;
            cf->alloc_size = 0;

            return CIO_CORRUPTED;
        }


        cf->data_size = content_size;
        cf->fs_size = fs_size;
    }
    else {
        cf->data_size = 0;
        cf->fs_size = 0;
    }

    ret = cio_file_format_check(ch, cf, cf->flags);

    if (ret != 0) {
        cio_log_error(ctx, "format check failed: %s/%s",
                      ch->st->name, ch->name);

        cio_file_native_unmap(cf);

        cf->data_size = 0;

        return CIO_CORRUPTED;
    }

    cf->st_content = cio_file_st_get_content(cf->map);
    cio_log_debug(ctx, "%s:%s mapped OK", ch->st->name, ch->name);

    /* The mmap succeeded, adjust the counters */
    cio_chunk_counter_total_up_add(ctx);

    return CIO_OK;
}

int cio_file_lookup_user(char *user, void **result)
{
    return cio_file_native_lookup_user(user, result);
}

int cio_file_lookup_group(char *group, void **result)
{
    return cio_file_native_lookup_group(group, result);
}

int cio_file_read_prepare(struct cio_ctx *ctx, struct cio_chunk *ch)
{
    return mmap_file(ctx, ch, 0);
}

int cio_file_content_copy(struct cio_chunk *ch,
                          void **out_buf, size_t *out_size)
{
    int ret;
    int set_down = CIO_FALSE;
    char *buf;
    char *data = NULL;
    size_t size;
    struct cio_file *cf = ch->backend;

    /* If the file content is already up, just do a copy of the memory map */
    if (cio_chunk_is_up(ch) == CIO_FALSE) {
        ret = cio_chunk_up_force(ch);
        if (ret != CIO_OK ){
            return CIO_ERROR;
        }
        set_down = CIO_TRUE;
    }

    size = cf->data_size;
    data = cio_file_st_get_content(cf->map);

    if (!data) {
        if (set_down == CIO_TRUE) {
            cio_chunk_down(ch);
        }
        return CIO_ERROR;
    }

    buf = malloc(size + 1);
    if (!buf) {
        cio_errno();
        if (set_down == CIO_TRUE) {
            cio_chunk_down(ch);
        }
        return CIO_ERROR;
    }
    memcpy(buf, data, size);
    buf[size] = '\0';

    *out_buf = buf;
    *out_size = size;

    if (set_down == CIO_TRUE) {
        cio_chunk_down(ch);
    }

    return CIO_OK;
}

/*
 * If the maximum number of 'up' chunks is reached, put this chunk
 * down (only at open time).
 */
static inline int open_and_up(struct cio_ctx *ctx)
{
    if (ctx->total_chunks_up >= ctx->max_chunks_up) {
        return CIO_FALSE;
    }

    return CIO_TRUE;
}

/*
 * Fetch the file size regardless of if we opened this file or not.
 */
size_t cio_file_real_size(struct cio_file *cf)
{
    size_t file_size;
    int    ret;

    ret = cio_file_native_get_size(cf, &file_size);

    if (ret != CIO_OK) {
        return 0;
    }

    return file_size;
}

static int format_acl_error_message(struct cio_ctx *ctx,
                                    struct cio_file *cf,
                                    char *output_buffer,
                                    size_t output_buffer_size)
{
    char *connector;
    int   result;
    char *group;
    char *user;

    user = ctx->options.user;
    group = ctx->options.group;
    connector = "with group";

    if (user == NULL) {
        user = "";
        connector = "";
    }

    if (group == NULL) {
        group = "";
        connector = "";
    }

    result = snprintf(output_buffer, output_buffer_size - 1,
                      "cannot change ownership of %s to %s %s %s",
                      cf->path, user, connector, group);

    if (result < 0) {
        return CIO_ERROR;
    }

    return CIO_OK;
}

/*
 * Open or create a data file: the following behavior is expected depending
 * of the passed flags:
 *
 * CIO_OPEN | CIO_OPEN_RW:
 *    - Open for read/write, if the file don't exist, it's created and the
 *      memory map size is assigned to the given value on 'size'.
 *
 * CIO_OPEN_RD:
 *    - If file exists, open it in read-only mode.
 */
struct cio_file *cio_file_open(struct cio_ctx *ctx,
                               struct cio_stream *st,
                               struct cio_chunk *ch,
                               int flags,
                               size_t size,
                               int *err)
{
    char             error_message[256];
    char            *path;
    int              ret;
    struct cio_file *cf;

    (void) size;

    ret = cio_file_native_filename_check(ch->name);
    if (ret != CIO_OK) {
        cio_log_error(ctx, "[cio file] invalid file name");

        return NULL;
    }

    path = cio_file_native_compose_path(ctx->options.root_path, st->name, ch->name);
    if (path == NULL) {
        return NULL;
    }

    /* Create file context */
    cf = calloc(1, sizeof(struct cio_file));
    if (!cf) {
        cio_errno();
        free(path);

        return NULL;
    }

    cf->fd = -1;
    cf->flags = flags;
    cf->page_size = cio_getpagesize();

    if (ctx->realloc_size_hint > 0) {
        cf->realloc_size = ctx->realloc_size_hint;
    }
    else {
        cf->realloc_size = CIO_REALLOC_HINT_MIN;
    }

    cf->taint_flag = CIO_FALSE;
    cf->st_content = NULL;
    cf->crc_cur = cio_crc32_init();
    cf->path = path;
    cf->map = NULL;
    cf->ctx = ctx;
    cf->auto_remap_warned = CIO_FALSE;
    cf->map_truncated_warned = CIO_FALSE;
    ch->backend = cf;

#ifdef _WIN32
    cf->backing_file = INVALID_HANDLE_VALUE;
    cf->backing_mapping = INVALID_HANDLE_VALUE;
#endif

#if defined (CIO_HAVE_FALLOCATE)
    cf->allocate_strategy = CIO_FILE_LINUX_FALLOCATE;
#endif

    /* Should we open and put this file up ? */
    ret = open_and_up(ctx);

    if (ret == CIO_FALSE) {
        /* we reached our limit, leave the file 'down' */
        cio_file_update_size(cf);

        /*
         * Due to he current resource limiting logic we could
         * get to this point without a file existing so we just
         * ignore the error.
         */

        return cf;
    }

    /* Open the file */
    ret = cio_file_native_open(cf);

    if (ret != CIO_OK) {
        free(path);
        free(cf);

        *err = ret;

        return NULL;
    }

    /* Update the file size field */
    ret = cio_file_update_size(cf);

    if (ret != CIO_OK) {
        cio_file_native_close(cf);

        free(path);
        free(cf);

        *err = ret;

        return NULL;
    }

    /* Set the file ownership and permissions */
    ret = cio_file_native_apply_acl_and_settings(ctx, cf);

    if (ret != CIO_OK) {
        *err = ret;

        ret = format_acl_error_message(ctx, cf, error_message, sizeof(error_message));

        if (ret != CIO_OK) {
            cio_log_error(ctx, "error generating error message for acl failure");
        }
        else {
            cio_log_error(ctx, error_message);
        }

        cio_file_native_close(cf);

        free(path);
        free(cf);

        return NULL;
    }

    /* Map the file */
    ret = mmap_file(ctx, ch, cf->fs_size);
    if (ret == CIO_ERROR || ret == CIO_CORRUPTED || ret == CIO_RETRY) {
        cio_file_native_close(cf);

        free(path);
        free(cf);

        *err = ret;

        return NULL;
    }

    *err = CIO_OK;

    return cf;
}

/* This function is used to delete a chunk by name, its only purpose is to delete
 * chunks that cannnot be loaded (otherwise we would set them down with the delete
 * flag set to TRUE).
 */
int cio_file_delete(struct cio_ctx *ctx, struct cio_stream *st, const char *name)
{
    char *path;
    int   ret;

    ret = cio_file_native_filename_check((char *) name);
    if (ret != CIO_OK) {
        cio_log_error(ctx, "[cio file] invalid file name");

        return CIO_ERROR;
    }

    path = cio_file_native_compose_path(ctx->options.root_path, st->name, (char *) name);
    if (path == NULL) {
        return CIO_ERROR;
    }

    ret = cio_file_native_delete_by_path(path);

    free(path);

    return ret;
}

/*
 * Put a file content back into memory, only IF it has been set 'down'
 * before.
 */
static int _cio_file_up(struct cio_chunk *ch, int enforced)
{
    int ret;
    struct cio_file *cf = (struct cio_file *) ch->backend;

    if (cf->map) {
        cio_log_error(ch->ctx, "[cio file] file is already mapped: %s/%s",
                      ch->st->name, ch->name);
        return CIO_ERROR;
    }

    if (cio_file_native_is_open(cf)) {
        cio_log_error(ch->ctx, "[cio file] file descriptor already exists: "
                      "%s:%s", ch->st->name, ch->name);
        return CIO_ERROR;
    }

    /*
     * Enforced mechanism provides safety based on Chunk I/O storage
     * pre-set limits.
     */
    if (enforced == CIO_TRUE) {
        ret = open_and_up(ch->ctx);
        if (ret == CIO_FALSE) {
            return CIO_ERROR;
        }
    }

    /* Open file */
    ret = cio_file_native_open(cf);

    if (ret != CIO_OK) {
        cio_log_error(ch->ctx, "[cio file] cannot open chunk: %s/%s",
                      ch->st->name, ch->name);
        return CIO_ERROR;
    }

    ret = cio_file_update_size(cf);
    if (ret != CIO_OK) {
        return CIO_ERROR;
    }

    /*
     * Map content:
     *
     * return values = CIO_OK, CIO_ERROR, CIO_CORRUPTED or CIO_RETRY
     */
    ret = mmap_file(ch->ctx, ch, cf->fs_size);
    if (ret == CIO_ERROR) {
        cio_log_error(ch->ctx, "[cio file] cannot map chunk: %s/%s",
                      ch->st->name, ch->name);
    }

    /*
     * 'ret' can still be CIO_CORRUPTED or CIO_RETRY on those cases we
     * close the file descriptor
     */
    if (ret == CIO_CORRUPTED || ret == CIO_RETRY) {
        /*
         * we just remove resources: close the recently opened file
         * descriptor, we never delete the Chunk at this stage since
         * the caller must take that action.
         */
        cio_file_native_close(cf);
    }

    return ret;
}

/*
 * Load a file using 'enforced' mode: do not load the file in memory
 * if we already passed memory or max_chunks_up restrictions.
 */
int cio_file_up(struct cio_chunk *ch)
{
    return _cio_file_up(ch, CIO_TRUE);
}

/* Load a file in non-enforced mode. This means it will load the file
 * in memory skipping restrictions set by configuration.
 *
 * The use case of this call is when the caller needs to write data
 * to a file which is down due to restrictions. But then the caller
 * must put the chunk 'down' again if that was it original status.
 */
int cio_file_up_force(struct cio_chunk *ch)
{
    return _cio_file_up(ch, CIO_FALSE);
}

int cio_file_update_size(struct cio_file *cf)
{
    int result;

    result = cio_file_native_get_size(cf, &cf->fs_size);

    if (result != CIO_OK) {
        cf->fs_size = 0;
    }

    return result;
}

/* Release memory and file descriptor resources but keep context */
int cio_file_down(struct cio_chunk *ch)
{
    int              ret;
    struct cio_file *cf;

    cf = (struct cio_file *) ch->backend;

    if (cf->map == NULL) {
        cio_log_error(ch->ctx, "[cio file] file is not mapped: %s/%s",
                      ch->st->name, ch->name);
        return -1;
    }

    /* unmap memory */
    ret = munmap_file(ch->ctx, ch);

    if (ret != 0) {
        return -1;
    }

    /* Allocated map size is zero */
    cf->alloc_size = 0;

    /* Update the file size */
    ret = cio_file_update_size(cf);

    if (ret != CIO_OK) {
        cio_errno();
    }

    /* Close file descriptor */
    ret = cio_file_native_close(cf);

    if (ret != CIO_OK) {
        cio_errno();
        return -1;
    }

    return 0;
}

void cio_file_close(struct cio_chunk *ch, int delete)
{
    int              ret;
    struct cio_file *cf;

    cf = (struct cio_file *) ch->backend;

    if (cf == NULL) {
        return;
    }

    /* Safe unmap of the file content */
    munmap_file(ch->ctx, ch);

    /* Close file descriptor */
    cio_file_native_close(cf);

    /* Should we delete the content from the file system ? */
    if (delete == CIO_TRUE) {
        ret = cio_file_native_delete(cf);

        if (ret != CIO_OK) {
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
    int meta_len;
    int pre_content;
    size_t av_size;
    size_t old_size;
    size_t new_size;
    struct cio_file *cf;

    if (count == 0) {
        /* do nothing */
        return 0;
    }

    if (!ch) {
        return -1;
    }

    cf = (struct cio_file *) ch->backend;

    if (cio_chunk_is_up(ch) == CIO_FALSE) {
        cio_log_error(ch->ctx, "[cio file] file is not mmap()ed: %s:%s",
                      ch->st->name, ch->name);
        return -1;
    }

    /* get available size */
    av_size = get_available_size(cf, &meta_len);

    /* validate there is enough space, otherwise resize */
    if (av_size < count) {
        /* Set the pre-content size (chunk header + metadata) */
        pre_content = (CIO_FILE_HEADER_MIN + meta_len);

        new_size = cf->alloc_size + cf->realloc_size;
        while (new_size < (pre_content + cf->data_size + count)) {
            new_size += cf->realloc_size;
        }

        old_size = cf->alloc_size;
        new_size = ROUND_UP(new_size, ch->ctx->page_size);

        ret = cio_file_resize(cf, new_size);

        if (ret != CIO_OK) {
            cio_log_error(ch->ctx,
                          "[cio_file] error setting new file size on write");
            return -1;
        }

        cio_log_debug(ch->ctx,
                      "[cio file] alloc_size from %lu to %lu",
                      old_size, new_size);
    }

    /* If crc_reset was toggled we know that data_size was
     * modified by cio_chunk_write_at which means we need
     * to update the header before we recalculate the checksum
     */
    if (cf->crc_reset) {
        cio_file_st_set_content_len(cf->map, cf->data_size);
    }

    if (ch->ctx->options.flags & CIO_CHECKSUM) {
        update_checksum(cf, (unsigned char *) buf, count);
    }

    cf->st_content = cio_file_st_get_content(cf->map);
    memcpy(cf->st_content + cf->data_size, buf, count);

    cf->data_size += count;
    cf->synced = CIO_FALSE;

    cio_file_st_set_content_len(cf->map, cf->data_size);

    cf->taint_flag = CIO_TRUE;

    return 0;
}

int cio_file_write_metadata(struct cio_chunk *ch, char *buf, size_t size)
{
    int ret;
    char *meta;
    char *cur_content_data;
    char *new_content_data;
    size_t new_size;
    size_t meta_av;
    struct cio_file *cf;

    cf = ch->backend;

    if (cio_file_is_up(ch, cf) == CIO_FALSE) {
        return -1;
    }

    /* Get metadata pointer */
    meta = cio_file_st_get_meta(cf->map);

    /* Check if meta already have some space available to overwrite */
    meta_av = cio_file_st_get_meta_len(cf->map);

    /* If there is some space available, just overwrite */
    if (meta_av >= size) {
        /* copy new metadata */
        memcpy(meta, buf, size);

        /* there are some remaining bytes, adjust.. */
        cur_content_data = cio_file_st_get_content(cf->map);
        new_content_data = meta + size;
        memmove(new_content_data, cur_content_data, cf->data_size);
        adjust_layout(ch, cf, size);

        return 0;
    }

    /*
     * The optimal case is if there is no content data, the non-optimal case
     * where we need to increase the memory map size, move the content area
     * bytes to a different position and write the metadata.
     *
     * Check if resize is needed before calculating content_av to avoid
     * unsigned underflow. We need: header + new_metadata + content_data <= alloc_size
     */
    if (cf->alloc_size < CIO_FILE_HEADER_MIN + size + cf->data_size) {
        new_size = CIO_FILE_HEADER_MIN + size + cf->data_size;

        ret = cio_file_resize(cf, new_size);

        if (ret != CIO_OK) {
            cio_log_error(ch->ctx,
                          "[cio meta] error resizing mapped file");

            return -1;
        }
    }

    /* get meta reference again in case the map address has changed */
    meta = cio_file_st_get_meta(cf->map);

    /* set new position for the content data */
    cur_content_data = cio_file_st_get_content(cf->map);
    new_content_data = meta + size;
    memmove(new_content_data, cur_content_data, cf->data_size);

    /* copy new metadata */
    memcpy(meta, buf, size);
    adjust_layout(ch, cf, size);

    return 0;
}

int cio_file_sync(struct cio_chunk *ch)
{
    int ret;
    int meta_len;
    size_t desired_size;
    size_t file_size;
    size_t av_size;
    struct cio_file *cf;

    if (ch == NULL) {
        return -1;
    }

    cf = (struct cio_file *) ch->backend;

    if (cf == NULL) {
        return -1;
    }

    if (cf->flags & CIO_OPEN_RD) {
        return 0;
    }

    /* If chunk is down (unmapped), there's nothing to sync */
    /* You can only write to a chunk when it's up, so if it's down, no pending changes exist */
    if (!cio_file_native_is_mapped(cf)) {
        return 0;
    }

    if (cf->synced == CIO_TRUE) {
        return 0;
    }

    ret = cio_file_native_get_size(cf, &file_size);

    if (ret != CIO_OK) {
        cio_file_report_os_error();

        return -1;
    }

    /* File trimming has been made opt-in because it causes
     * performance degradation and excessive fragmentation
     * in XFS.
     */
    if ((ch->ctx->options.flags & CIO_TRIM_FILES) != 0) {
        /* If there are extra space, truncate the file size */
        av_size = get_available_size(cf, &meta_len);

        if (av_size > 0) {
            desired_size = cf->alloc_size - av_size;
        }
        else if (cf->alloc_size > file_size) {
            desired_size = cf->alloc_size;
        }
        else {
            desired_size = file_size;
        }

        if (desired_size != file_size) {
            /* When file trimming is enabled we still round the file size up
             * to the memory page size because even though not explicitly
             * stated there seems to be a performance degradation issue that
             * correlates with sub-page mapping.
             */
            desired_size = ROUND_UP(desired_size, ch->ctx->page_size);

            ret = cio_file_resize(cf, desired_size);

            if (ret != CIO_OK) {
                cio_log_error(ch->ctx,
                              "[cio file sync] error adjusting size at: "
                              " %s/%s", ch->st->name, ch->name);

                return ret;
            }
        }
    }

    /* Finalize CRC32 checksum */
    if (ch->ctx->options.flags & CIO_CHECKSUM) {
        finalize_checksum(cf);
    }

    /* Commit changes to disk */
    ret = cio_file_native_sync(cf, ch->ctx->options.flags);

    if (ret != CIO_OK) {
        return -1;
    }

    cf->synced = CIO_TRUE;

    ret = cio_file_update_size(cf);

    if (ret != CIO_OK) {
        return -1;
    }

    cio_log_debug(ch->ctx, "[cio file] synced at: %s/%s",
                  ch->st->name, ch->name);

    return 0;
}

int cio_file_resize(struct cio_file *cf, size_t new_size)
{
    int    inner_result;
    size_t mapped_size;
    int    mapped_flag;
    int    result;

    mapped_flag = cio_file_native_is_mapped(cf);
    mapped_size = cf->alloc_size;

#ifdef _WIN32
    if (mapped_flag) {
        result = cio_file_native_unmap(cf);

        if (result != CIO_OK) {
            return result;
        }
    }
#endif

    result = cio_file_native_resize(cf, new_size);

    if (result != CIO_OK) {
        cio_file_native_report_os_error();

#ifdef _WIN32
        if (mapped_flag) {
            inner_result = cio_file_native_map(cf, mapped_size);
        }
#endif

        return result;
    }

    if (mapped_flag) {
#ifdef _WIN32
        result = cio_file_native_map(cf, new_size);
#else
        result = cio_file_native_remap(cf, new_size);
#endif

        if (result != CIO_OK) {
            return result;
        }
    }

    (void) mapped_size;
    (void) inner_result;

    return CIO_OK;
}

char *cio_file_hash(struct cio_file *cf)
{
    return (cf->map + 2);
}

void cio_file_hash_print(struct cio_file *cf)
{
    printf("crc cur=%lu\n", (long unsigned int)cf->crc_cur);
    printf("%08lx\n", (long unsigned int ) cf->crc_cur);
}

/* Dump files from given stream */
void cio_file_scan_dump(struct cio_ctx *ctx, struct cio_stream *st)
{
    int ret;
    int meta_len;
    int set_down = CIO_FALSE;
    char *p;
    crc_t crc;
    crc_t crc_fs;
    char tmp[PATH_MAX];
    struct mk_list *head;
    struct cio_chunk *ch;
    struct cio_file *cf;

    mk_list_foreach(head, &st->chunks) {
        ch = mk_list_entry(head, struct cio_chunk, _head);
        cf = ch->backend;

        if (cio_file_is_up(ch, cf) == CIO_FALSE) {
            ret = cio_file_up(ch);
            if (ret == -1) {
                continue;
            }
            set_down = CIO_TRUE;
        }

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
        if (ctx->options.flags & CIO_CHECKSUM) {
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
        printf("meta_len=%d, data_size=%zu, crc=%08x\n",
               meta_len, cf->data_size, (uint32_t) crc_fs);

        if (set_down == CIO_TRUE) {
            cio_file_down(ch);
        }
    }
}

/* Check if a file content is up in memory and a file descriptor is set */
int cio_file_is_up(struct cio_chunk *ch, struct cio_file *cf)
{
    (void) ch;

    if (cio_file_native_is_open(cf) &&
        cio_file_native_is_mapped(cf)) {
        return CIO_TRUE;
    }

    return CIO_FALSE;
}
