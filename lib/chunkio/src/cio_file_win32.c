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

#include <inttypes.h>
#include <stdio.h>

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_crc32.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_st.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>

/*
 * Implement file chunk API for Windows.
 *
 * * This module uses "files" as shared buffers in lieu of mmap(2).
 *
 * * Every chunk operation is done directly to the underlying file
 *   through ReadFile/WriteFile API.
 *
 * * In this module, cf->map is a plain buffer allocated by malloc.
 *   cio_file_read_prepare() is in charge of keeping its content
 *   in sync with the underlying file.
 *
 * NOTE: there is a shared memory API named CreateFileMapping(),
 * but it's not usable in this module.
 *
 * The reason is that a file mapping prevents file resizes. Since
 * there can be several cio_file instances on the same file (see
 * cio_scan_stream_files() in cio_scan.c), it ends up preventing
 * everyone from resizing that file.
 */

#define win32_chunk_error(ch, msg) \
        cio_log_error((ch)->ctx, "%s on '%s/%s' (%s() line=%i)", \
                      (msg), (ch)->st->name, (ch)->name, __func__, __LINE__)

static char init_bytes[] = {
    /* file type (2 bytes)    */
    CIO_FILE_ID_00, CIO_FILE_ID_01,

    /* crc32 (4 bytes) in network byte order */
    0x41, 0xd9, 0x12, 0xff,

    /* padding bytes (we have 16 extra bytes */
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,

    /* metadata length (2 bytes) */
    0x00, 0x00
};

/*
 * Read N bytes from file. Return 0 on success, and -1 on
 * failure (including a partial read).
 */
static int read_file(HANDLE h, char *buf, uint64_t size)
{
    uint64_t read = 0;
    DWORD len;
    DWORD bytes;

    while (read < size) {
        len = (int) min(size - read, 65536);
        if (!ReadFile(h, buf + read, len, &bytes, NULL)) {
            cio_winapi_error();
            return -1;
        }
        if (bytes == 0) {
            cio_winapi_error();
            return -1;  /* EOF */
        }
        read += bytes;
    }
    return 0;
}

static int write_file(HANDLE h, const char *buf, uint64_t size)
{
    uint64_t written = 0;
    DWORD len;
    DWORD bytes;

    while (written < size) {
        len = (int) min(size - written, 65536);
        if (!WriteFile(h, buf + written, len, &bytes, NULL)) {
            cio_winapi_error();
            return -1;
        }
        written += bytes;
    }
    return 0;
}

static int seek_file(HANDLE h, int64_t offset)
{
    LARGE_INTEGER liDistanceToMove;

    liDistanceToMove.QuadPart = offset;

    if (!SetFilePointerEx(h, liDistanceToMove, NULL, FILE_BEGIN)) {
        cio_winapi_error();
        return -1;
    }
    return 0;
}

static int64_t get_file_size(HANDLE h)
{
    LARGE_INTEGER liFileSize;

    if (!GetFileSizeEx(h, &liFileSize)) {
        cio_winapi_error();
        return -1;
    };
    return liFileSize.QuadPart;
}

/*
 * Create an empty file chunk. This function erases all
 * the data inside the given chunk.
 */
static int init_chunk(struct cio_chunk *ch)
{
    struct cio_file *cf = (struct cio_file *) ch->backend;

    if (seek_file(cf->h, 0)) {
        win32_chunk_error(ch, "[cio file] cannot seek");
        return -1;
    }

    if (write_file(cf->h, init_bytes, sizeof(init_bytes))) {
        win32_chunk_error(ch, "[cio file] cannot write data");
        return -1;
    }

    if (!SetEndOfFile(cf->h)) {
        cio_winapi_error();
        return -1;
    }

    cf->fs_size = sizeof(init_bytes);
    cf->data_size = 0;
    return 0;
}

/*
 * Read the meta size field in file. Return an integer between
 * [0, 0xffff] on success, and -1 on failure.
 */
static int read_meta_size(struct cio_chunk *ch)
{
    uint16_t meta_size_be;
    struct cio_file *cf = (struct cio_file *) ch->backend;

    if (seek_file(cf->h, CIO_FILE_CONTENT_OFFSET)) {
        win32_chunk_error(ch, "[cio file] cannot seek");
        return -1;
    }

    if (read_file(cf->h, (char *) &meta_size_be, 2)) {
        win32_chunk_error(ch, "[cio file] cannot read meta size");
        return -1;
    }

    return _byteswap_ushort(meta_size_be);
}

/*
 * Compute CRC32 checksum by scanning through the file.
 * Return 0 on success, and -1 on error.
 */
static int calc_checksum(struct cio_file *cf, crc_t *out)
{
    char buf[1024];
    int len;
    crc_t val = cio_crc32_init();
    uint64_t read = 0;
    uint64_t size = 0;

    if (seek_file(cf->h, CIO_FILE_CONTENT_OFFSET)) {
        return -1;
    }

    size = cf->fs_size - CIO_FILE_CONTENT_OFFSET;

    while (read < size) {
        len = (int) min(size - read, 1024);
        if (read_file(cf->h, buf, len)) {
            return -1;
        }
        val = cio_crc32_update(val, buf, len);
        read += len;
    }
    *out = cio_crc32_finalize(val);
    return 0;
}

/*
 * Compute CRC32 and compare it against the checksum stored
 * in the file. Return 0 on success, -3 on content corruption
 * and -1 on error.
 */
static int verify_checksum(struct cio_chunk *ch)
{
    crc_t hash;
    crc_t hash_be;
    struct cio_file *cf = (struct cio_file *) ch->backend;

    if (calc_checksum(cf, &hash)) {
        win32_chunk_error(ch, "[cio file] cannot compute checksum");
        return CIO_ERROR;
    }

    if (seek_file(cf->h, 2)) {
        win32_chunk_error(ch, "[cio file] cannot seek");
        return CIO_ERROR;
    }

    /*
     * cio_file.c stores CRC32 in big endian order and Windows
     * is a little endian.
     */
    if (read_file(cf->h, (char *) &hash_be, 4)) {
        win32_chunk_error(ch, "[cio file] cannot read hash");
        return CIO_ERROR;
    }

    if (hash != (crc_t) _byteswap_ulong(hash_be)) {
        cio_log_error(ch->ctx, "[cio file] hash does not match (%u != %u)",
                      hash, _byteswap_ulong(hash_be));
        return CIO_CORRUPTED;
    }

    return CIO_OK;
}

/*
 * Return the number of active file chunks. This function is used
 * to check "max_chunks_up" limit.
 */
static int count_open_file_chunks(struct cio_ctx *ctx)
{
    int total = 0;
    struct mk_list *head;
    struct mk_list *f_head;
    struct cio_file *file;
    struct cio_chunk *ch;
    struct cio_stream *stream;

    mk_list_foreach(head, &ctx->streams) {
        stream = mk_list_entry(head, struct cio_stream, _head);

        if (stream->type == CIO_STORE_MEM) {
            continue;
        }

        mk_list_foreach(f_head, &stream->chunks) {
            ch = mk_list_entry(f_head, struct cio_chunk, _head);
            file = (struct cio_file *) ch->backend;

            if (cio_file_is_up(NULL, file) == CIO_TRUE) {
                total++;
            }
        }
    }
    return total;
}

static char *create_path(struct cio_chunk *ch)
{
    char *path;
    size_t len;
    int ret;

    len = strlen(ch->ctx->options.root_path) + strlen(ch->st->name) + strlen(ch->name);
    len += 3;

    path = calloc(1, len);
    if (!path) {
        cio_errno();
        return NULL;
    }

    ret = sprintf_s(path, len, "%s\\%s\\%s",
                    ch->ctx->options.root_path, ch->st->name, ch->name);
    if (ret < 0) {
        cio_errno();
        free(path);
        return NULL;
    }
    return path;
}

static int is_valid_file_name(const char *name)
{
    size_t len;

    len = strlen(name);
    if (len == 0) {
        return 0;
    }
    else if (len == 1) {
        if (name[0] == '\\' || name[0] == '.' || name[0] == '/') {
            return 0;
        }
    }
    return 1;
}

/*
 * Fetch the file size regardless of if we opened this file or not.
 */
size_t cio_file_real_size(struct cio_file *cf)
{
    int ret;
#ifdef _WIN64
    struct _stat64 st;
#else
    struct _stat32 st;
#endif

    /* Store the current real size */
#ifdef _WIN64
    ret = _stat64(cf->path, &st);
#else
    ret = _stat32(cf->path, &st);
#endif

    if (ret != 0) {
        cio_errno();
        return 0;
    }

    return st.st_size;
}

/*
 * Return a new file chunk instance. This is the starting
 * point for manipulating file chunks.
 */
struct cio_file *cio_file_open(struct cio_ctx *ctx,
                               struct cio_stream *st,
                               struct cio_chunk *ch,
                               int flags,
                               size_t size,
                               int *err)
{
    struct cio_file *cf;

    if (!is_valid_file_name(ch->name)) {
        win32_chunk_error(ch, "[cio file] invalid file name");
        return NULL;
    }

    cf = calloc(1, sizeof(struct cio_file));
    if (!cf) {
        cio_errno();
        return NULL;
    }

    cf->path = create_path(ch);
    if (cf->path == NULL) {
        win32_chunk_error(ch, "[cio file] cannot create path");
        free(cf);
        return NULL;
    }

    cf->fd = -1;
    cf->flags = flags;
    cf->realloc_size = 0;
    cf->st_content = NULL;
    cf->crc_cur = 0;
    cf->map = NULL;
    cf->h = INVALID_HANDLE_VALUE;
    ch->backend = cf;

    if (count_open_file_chunks(ch->ctx) >= ctx->max_chunks_up) {
        cio_log_debug(ch->ctx, "[cio file] create a chunk %s/%s (down)",
                      st->name, ch->name);
        return cf;  /* this is how cio_file.c behaves */
    }

    if (cio_file_up(ch)) {
        win32_chunk_error(ch, "[cio file] cannot activate chunk");
        cio_file_close(ch, CIO_FALSE);
        return NULL;
    }

    if (ch->ctx->options.flags & CIO_CHECKSUM) {
        if (verify_checksum(ch)) {
            win32_chunk_error(ch, "[cio file] cannot verify checksum");
            cio_file_close(ch, CIO_FALSE);
            return NULL;
        }
    }

    return cf;
}

/*
 * Deallocate a file chunk instance.
 */
void cio_file_close(struct cio_chunk *ch, int delete)
{
    struct cio_file *cf = (struct cio_file *) ch->backend;

    if (!cf) {
        return;
    }

    if (cio_file_is_up(ch, ch->backend)) {
        cio_file_down(ch);
    }

    if (delete == CIO_TRUE) {
        if (!DeleteFileA(cf->path)) {
            cio_winapi_error();
        }
    }
    free(cf->map);
    free(cf->path);
    free(cf);
}

/*
 * Append data into the end of the file chunk.
 */
int cio_file_write(struct cio_chunk *ch, const void *buf, size_t count)
{
    struct cio_file *cf = (struct cio_file *) ch->backend;
    int meta_size;

    if (count == 0) {
        return 0;
    }

    if (!cio_file_is_up(ch, ch->backend)) {
        win32_chunk_error(ch, "[cio file] chunk is not up");
        return -1;
    }

    meta_size = read_meta_size(ch);
    if (meta_size < 0) {
        win32_chunk_error(ch, "[cio file] cannot read meta size");
        return -1;
    }

    if (seek_file(cf->h, CIO_FILE_HEADER_MIN + meta_size + cf->data_size)) {
        win32_chunk_error(ch, "[cio file] cannot seek");
        return -1;
    }

    if (write_file(cf->h, buf, count)) {
        win32_chunk_error(ch, "[cio file] cannot write data");
        return -1;
    }

    if (!SetEndOfFile(cf->h)) {
        cio_winapi_error();
        return -1;
    }

    cf->data_size += count;
    cf->fs_size = CIO_FILE_HEADER_MIN + meta_size + cf->data_size;
    cf->synced = CIO_FALSE;
    cf->map_synced = CIO_FALSE;

    return 0;
}

int create_space_for_meta(struct cio_chunk *ch, uint16_t meta_size)
{
    uint16_t prev_size;
    struct cio_file *cf = (struct cio_file *) ch->backend;
    char *buf;
    char *ptr;

    if (cf->data_size == 0) {
        return 0;  /* No need for relocation */
    }

    buf = malloc(cf->fs_size);
    if (buf == NULL) {
        cio_errno();
        return -1;
    }

    if (seek_file(cf->h, 0)) {
        win32_chunk_error(ch, "[cio file] cannot seek");
        free(buf);
        return -1;
    }

    if (read_file(cf->h, buf, cf->fs_size)) {
        win32_chunk_error(ch, "[cio file] cannot read data");
        free(buf);
        return -1;
    }

    ptr = cio_file_st_get_content(buf);
    prev_size = cio_file_st_get_meta_len(buf);

    if (prev_size == meta_size) {
        free(buf);
        return 0;  /* nothing to do */
    }

    if (seek_file(cf->h, CIO_FILE_HEADER_MIN + meta_size)) {
        win32_chunk_error(ch, "[cio file] cannot seek");
        free(buf);
        return -1;
    }

    if (write_file(cf->h, ptr, cf->data_size)) {
        win32_chunk_error(ch, "[cio file] cannot write data");
        free(buf);
        return -1;
    }
    free(buf);

    cf->fs_size = CIO_FILE_HEADER_MIN + meta_size + cf->data_size;

    return 0;
}

int cio_file_write_metadata(struct cio_chunk *ch, char *buf, size_t size)
{
    struct cio_file *cf = (struct cio_file *) ch->backend;
    uint16_t meta_size = (uint16_t) size;
    uint16_t meta_size_be = _byteswap_ushort(meta_size);

    if (!cio_file_is_up(ch, cf)) {
        win32_chunk_error(ch, "[cio file] chunk is not up");
        return -1;
    }

    if (size > UINT16_MAX) {
        cio_log_error(ch->ctx, "[cio file] too large meta (%zu bytes) %s:%s",
                      size, ch->st->name, ch->name);
        return -1;
    }

    if (create_space_for_meta(ch, meta_size)) {
        cio_log_error(ch->ctx, "[cio file] fail to allocate %zu bytes %s:%s",
                      size, ch->st->name, ch->name);
        return -1;
    }

    if (seek_file(cf->h, CIO_FILE_CONTENT_OFFSET)) {
        win32_chunk_error(ch, "[cio file] cannot seek");
        return -1;
    }

    if (write_file(cf->h, (char *) &meta_size_be, 2)) {
        win32_chunk_error(ch, "[cio file] cannot write meta size");
        return -1;
    }

    if (write_file(cf->h, buf, meta_size)) {
        win32_chunk_error(ch, "[cio file] cannot write meta data");
        return -1;
    }
    cf->synced = CIO_FALSE;
    cf->map_synced = CIO_FALSE;

    return 0;
}

int cio_file_sync(struct cio_chunk *ch)
{
    struct cio_file *cf = (struct cio_file *) ch->backend;
    crc_t hash, hash_be;

    if (calc_checksum(cf, &hash)) {
        win32_chunk_error(ch, "[cio file] cannot compute checksum");
        return -1;
    }

    if (cf->flags & CIO_OPEN_RD) {
        cio_log_debug(ch->ctx, "[cio file] chunk '%s:%s' is read only",
                      ch->st->name, ch->name);
        return 0;
    }

    /* Windows is little endian */
    hash_be = _byteswap_ulong(hash);

    if (seek_file(cf->h, 2)) {
        win32_chunk_error(ch, "[cio file] cannot seek");
        return -1;
    }

    if (write_file(cf->h, (char *) &hash_be, 4)) {
        win32_chunk_error(ch, "[cio file] cannot write hash");
        return -1;
    }

    if (!FlushFileBuffers(cf->h)) {
        cio_winapi_error();
        return -1;
    }

    /* Reflect checksum to keep map synced */
    if (cf->map) {
        memcpy(cf->map + 2, &hash_be, 4);
    }

    cf->crc_be = hash_be;
    cf->synced = CIO_TRUE;

    cio_log_debug(ch->ctx, "[cio file] synced at: %s/%s",
                  ch->st->name, ch->name);
    return 0;
}

int cio_file_fs_size_change(struct cio_file *cf, size_t new_size)
{
    if (seek_file(cf->h, new_size)) {
        return -1;
    }

    if (!SetEndOfFile(cf->h)) {
        cio_winapi_error();
        return -1;
    }

    cf->data_size += (cf->fs_size - new_size);
    cf->fs_size = new_size;
    return 0;
}

/*
 * Return the char pointer to the CRC32 field (big endian).
 */
char *cio_file_hash(struct cio_file *cf)
{
    return (char *) &cf->crc_be;
}

void cio_file_hash_print(struct cio_file *cf)
{
    crc_t hash;

    if (calc_checksum(cf, &hash)) {
        printf("failed to compute hash");
        return;
    }

    printf("crc =%u\n", hash);
    printf("%08x\n", hash);
}

void cio_file_calculate_checksum(struct cio_file *cf, crc_t *out)
{
    calc_checksum(cf, out);
}

void cio_file_scan_dump(struct cio_ctx *ctx, struct cio_stream *st)
{
    (void *) ctx;
    (void *) st;
    return;
}

/*
 * Copy the file content into memory buffer so that the caller
 * can access the chunk data.
 */
int cio_file_read_prepare(struct cio_ctx *ctx, struct cio_chunk *ch)
{
    (void *) ctx;
    char *buf;
    struct cio_file *cf = ch->backend;
    int64_t size;

    if (cf->map && cf->map_synced == CIO_TRUE) {
        return 0;  /* no need to update */
    }

    size = get_file_size(cf->h);
    if (size <= 0) {
        win32_chunk_error(ch, "[cio file] cannot get file size");
        return -1;
    }

    buf = malloc(size);
    if (buf == NULL) {
        cio_errno();
        return -1;
    }

    if (seek_file(cf->h, 0)) {
        win32_chunk_error(ch, "[cio file] cannot seek");
        free(buf);
        return -1;
    }

    if (read_file(cf->h, buf, size)) {
        win32_chunk_error(ch, "[cio file] cannot read data");
        free(buf);
        return -1;
    }

    free(cf->map);
    cf->map = buf;
    cf->map_synced = CIO_TRUE;
    return 0;
}

int cio_file_content_copy(struct cio_chunk *ch,
                          void **out_buf, size_t *out_size)
{
    char *buf;
    int ret = -1;
    int meta_size;
    int set_down = CIO_FALSE;
    struct cio_file *cf = ch->backend;

    if (cio_chunk_is_up(ch) == CIO_FALSE) {
        ret = cio_chunk_up_force(ch);
        if (ret == -1){
            win32_chunk_error(ch, "[cio file] cannot activate chunk");
            return ret;
        }
        set_down = CIO_TRUE;
    }

    meta_size = read_meta_size(ch);
    if (meta_size < 0) {
        win32_chunk_error(ch, "[cio file] cannot read meta size");
        goto done;
    }

    buf = calloc(1, cf->data_size + 1);
    if (buf == NULL) {
        cio_errno();
        goto done;
    }

    if (seek_file(cf->h, CIO_FILE_HEADER_MIN + meta_size)) {
        win32_chunk_error(ch, "[cio file] cannot seek");
        free(buf);
        goto done;
    }

    if (read_file(cf->h, buf, cf->data_size)) {
        win32_chunk_error(ch, "[cio file] cannot read data");
        free(buf);
        goto done;
    }

    *out_buf = buf;
    *out_size = cf->data_size;
    ret = 0;

done:
    if (set_down == CIO_TRUE) {
        cio_chunk_down(ch);
    }
    return ret;
}

int cio_file_is_up(struct cio_chunk *ch, struct cio_file *cf)
{
    (void) ch;

    if (cf->h != INVALID_HANDLE_VALUE) {
        return CIO_TRUE;
    }

    return CIO_FALSE;
}

int cio_file_down(struct cio_chunk *ch)
{
    struct cio_file *cf = (struct cio_file *) ch->backend;

    if (!cio_file_is_up(ch, cf)) {
        win32_chunk_error(ch, "[cio file] chunk is not up");
        return -1;
    }

    CloseHandle(cf->h);
    cf->h = INVALID_HANDLE_VALUE;
    return 0;
}

int cio_file_up(struct cio_chunk *ch)
{
    if (cio_file_is_up(ch, ch->backend)) {
        win32_chunk_error(ch, "[cio file] chunk is already up");
        return -1;
    }

    if (count_open_file_chunks(ch->ctx) >= ch->ctx->max_chunks_up) {
        win32_chunk_error(ch, "[cio file] too many open chunks");
        return -1;
    }
    return cio_file_up_force(ch);
}

static SID *perform_sid_lookup(char *account_name, SID_NAME_USE *result_sid_type)
{
    DWORD        referenced_domain_name_length;
    char         referenced_domain_name[256];
    SID         *reallocated_sid_buffer;
    DWORD        sid_buffer_size;
    size_t       retry_index;
    SID         *sid_buffer;
    SID_NAME_USE sid_type;
    int          result;

    referenced_domain_name_length = 256;
    sid_buffer_size = 256;

    sid_buffer = calloc(1, sid_buffer_size);

    if (sid_buffer == NULL) {
        cio_winapi_error();

        return NULL;
    }

    result = 0;

    for (retry_index = 0 ; retry_index < 5 && !result ; retry_index++) {
        result = LookupAccountNameA(NULL,
                                    account_name,
                                    sid_buffer,
                                    &sid_buffer_size,
                                    referenced_domain_name,
                                    &referenced_domain_name_length,
                                    &sid_type);

        if (!result) {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                sid_buffer_size *= 2;

                reallocated_sid_buffer = realloc(sid_buffer, sid_buffer_size);

                if (reallocated_sid_buffer == NULL) {
                    cio_winapi_error();
                    free(sid_buffer);

                    return NULL;
                }
            }
            else {
                cio_winapi_error();
                free(sid_buffer);

                return NULL;
            }
        }
    }

    if (result_sid_type != NULL) {
        *result_sid_type = sid_type;
    }

    return sid_buffer;
}

static int cio_file_lookup_entity(char *name,
                                  void **result,
                                  SID_NAME_USE desired_sid_type)
{
    SID_NAME_USE result_sid_type;

    *result = (void **) perform_sid_lookup(name, &result_sid_type);

    if (*result == NULL) {
        return CIO_ERROR;
    }

    if (desired_sid_type != result_sid_type) {
        free(*result);
        *result = NULL;

        return CIO_ERROR;
    }

    return CIO_OK;
}

int cio_file_lookup_user(char *user, void **result)
{
    return cio_file_lookup_entity(user, result, SidTypeUser);
}

int cio_file_lookup_group(char *group, void **result)
{
    return cio_file_lookup_entity(group, result, SidTypeGroup);
}

static DWORD cio_file_win_chown(char *path, SID *user, SID *group)
{
    int result;

    /* Ownership here does not work in the same way it works in unixes
     * so specifying both a user and group will end up with the group
     * overriding the user if possible which can cause some misunderstandings.
     */

    result = ERROR_SUCCESS;

    if (user != NULL) {
        result = SetNamedSecurityInfoA(path, SE_FILE_OBJECT,
                                       OWNER_SECURITY_INFORMATION,
                                       user, NULL, NULL, NULL);
    }

    if (group != NULL && result == ERROR_SUCCESS) {
        result = SetNamedSecurityInfoA(path, SE_FILE_OBJECT,
                                       GROUP_SECURITY_INFORMATION,
                                       group, NULL, NULL, NULL);
    }

    return result;
}

static int apply_file_ownership_and_acl_settings(struct cio_ctx *ctx, char *path)
{
    char *connector;
    int   result;
    char *group;
    char *user;

    if (ctx->processed_user != NULL) {
        result = cio_file_win_chown(path, ctx->processed_user, ctx->processed_group);

        if (result != CIO_OK) {
            cio_errno();

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

            cio_log_error(ctx, "cannot change ownership of %s to %s %s %s",
                          path, user, connector, group);

            return CIO_ERROR;
        }
    }

    return CIO_OK;
}

int cio_file_up_force(struct cio_chunk *ch)
{
    struct cio_file *cf = (struct cio_file *) ch->backend;
    int dwDesiredAccess = 0;
    int dwCreationDisposition = 0;
    int meta_size;
    int64_t size;
    int ret;

    if (cio_file_is_up(ch, cf)) {
        win32_chunk_error(ch, "[cio file] chunk is already up");
        return -1;
    }

    if (cf->flags & CIO_OPEN) {
        dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
        dwCreationDisposition = OPEN_ALWAYS;
    }
    else if (cf->flags & CIO_OPEN_RD) {
        dwDesiredAccess = GENERIC_READ;
        dwCreationDisposition = OPEN_EXISTING;
    }

    cf->h = CreateFileA(cf->path,
                        dwDesiredAccess,
                        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        dwCreationDisposition,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);

    if (cf->h == INVALID_HANDLE_VALUE) {
        cio_winapi_error();
        win32_chunk_error(ch, "[cio file] cannot open");
        return -1;
    }

    ret = apply_file_ownership_and_acl_settings(ch->ctx, cf->path);
    if (ret == CIO_ERROR) {
        CloseHandle(cf->h);
        cf->h = INVALID_HANDLE_VALUE;

        return -1;
    }

    size = get_file_size(cf->h);
    if (size < 0) {
        win32_chunk_error(ch, "[cio file] cannot get file size");
        return -1;
    }
    else if (size == 0) {
        return init_chunk(ch);
    }

    meta_size = read_meta_size(ch);
    if (meta_size < 0) {
        win32_chunk_error(ch, "[cio file] cannot read meta size");
        return -1;
    }

    cf->fs_size = size;
    cf->data_size = size - meta_size - CIO_FILE_HEADER_MIN;

    return 0;
}
