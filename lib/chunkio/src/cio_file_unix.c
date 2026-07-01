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
#include <sys/mman.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>

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


int cio_file_native_unmap(struct cio_file *cf)
{
    int ret;

    if (cf == NULL) {
        return CIO_ERROR;
    }

    if (!cio_file_native_is_mapped(cf)) {
        return CIO_OK;
    }

    ret = munmap(cf->map, cf->alloc_size);

    if (ret != 0) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    cf->alloc_size = 0;
    cf->map = NULL;
    cf->map_truncated_warned = CIO_FALSE;

    return CIO_OK;
}

int cio_file_native_map(struct cio_file *cf, size_t map_size)
{
    int flags;

    if (cf == NULL) {
        return CIO_ERROR;
    }

    if (!cio_file_native_is_open(cf)) {
        return CIO_ERROR;
    }

    if (cio_file_native_is_mapped(cf)) {
        return CIO_OK;
    }

    if (cf->flags & CIO_OPEN_RW) {
        flags = PROT_READ | PROT_WRITE;
    }
    else if (cf->flags & CIO_OPEN_RD) {
        flags = PROT_READ;
    }
    else {
        return CIO_ERROR;
    }

    cf->map = mmap(0, map_size, flags, MAP_SHARED, cf->fd, 0);

    if (cf->map == MAP_FAILED) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    cf->alloc_size = map_size;

    return CIO_OK;
}

int cio_file_native_remap(struct cio_file *cf, size_t new_size)
{
    int   result;
    void *tmp;

    result = 0;

/* OSX mman does not implement mremap or MREMAP_MAYMOVE. */
#ifndef MREMAP_MAYMOVE
    result = cio_file_native_unmap(cf);

    if (result == -1) {
        return result;
    }

    tmp = mmap(0, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, cf->fd, 0);
#else
    (void) result;

    tmp = mremap(cf->map, cf->alloc_size, new_size, MREMAP_MAYMOVE);
#endif

    if (tmp == MAP_FAILED) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    cf->map = tmp;
    cf->alloc_size = new_size;

    return CIO_OK;
}

int cio_file_native_lookup_user(char *user, void **result)
{
    long           query_buffer_size;
    struct passwd *query_result;
    char          *query_buffer;
    struct passwd  passwd_entry;
    int            api_result;

    if (user == NULL) {
        *result = calloc(1, sizeof(uid_t));

        if (*result == NULL) {
            cio_file_native_report_runtime_error();

            return CIO_ERROR;
        }

        **(uid_t **) result = (uid_t) -1;
    }

    query_buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);

    if (query_buffer_size == -1) {
        query_buffer_size = 4096 * 10;
    }

    query_buffer = calloc(1, query_buffer_size);

    if (query_buffer == NULL) {
        return CIO_ERROR;
    }

    query_result = NULL;

    api_result = getpwnam_r(user, &passwd_entry, query_buffer,
                            query_buffer_size, &query_result);

    if (api_result != 0 || query_result == NULL) {
        cio_file_native_report_os_error();

        free(query_buffer);

        return CIO_ERROR;
    }

    *result = calloc(1, sizeof(uid_t));

    if (*result == NULL) {
        cio_file_native_report_runtime_error();

        free(query_buffer);

        return CIO_ERROR;
    }

    **(uid_t **) result = query_result->pw_uid;

    free(query_buffer);

    return CIO_OK;
}

int cio_file_native_lookup_group(char *group, void **result)
{
    long           query_buffer_size;
    struct group  *query_result;
    char          *query_buffer;
    struct group   group_entry;
    int            api_result;

    if (group == NULL) {
        *result = calloc(1, sizeof(gid_t));

        if (*result == NULL) {
            cio_file_native_report_runtime_error();

            return CIO_ERROR;
        }

        **(gid_t **) result = (gid_t) -1;
    }

    query_buffer_size = sysconf(_SC_GETGR_R_SIZE_MAX);

    if (query_buffer_size == -1) {
        query_buffer_size = 4096 * 10;
    }

    query_buffer = calloc(1, query_buffer_size);

    if (query_buffer == NULL) {
        return CIO_ERROR;
    }

    query_result = NULL;

    api_result = getgrnam_r(group, &group_entry, query_buffer,
                            query_buffer_size, &query_result);

    if (api_result != 0 || query_result == NULL) {
        cio_file_native_report_os_error();

        free(query_buffer);

        return CIO_ERROR;
    }

    *result = calloc(1, sizeof(gid_t));

    if (*result == NULL) {
        cio_file_native_report_runtime_error();

        free(query_buffer);

        return CIO_ERROR;
    }

    **(gid_t **) result = query_result->gr_gid;

    free(query_buffer);

    return CIO_OK;
}

int cio_file_native_apply_acl_and_settings(struct cio_ctx *ctx, struct cio_file *cf)
{
    mode_t filesystem_acl;
    gid_t  numeric_group;
    uid_t  numeric_user;
    int    result;

    numeric_group = -1;
    numeric_user = -1;

    if (ctx->processed_user != NULL) {
        numeric_user = *(uid_t *) ctx->processed_user;
    }

    if (ctx->processed_group != NULL) {
        numeric_group = *(gid_t *) ctx->processed_group;
    }

    if (numeric_user != -1 || numeric_group != -1) {
        result = chown(cf->path, numeric_user, numeric_group);

        if (result == -1) {
            cio_file_native_report_os_error();

            return CIO_ERROR;
        }
    }

    if (ctx->options.chmod != NULL) {
        filesystem_acl = strtoul(ctx->options.chmod, NULL, 8);

        result = chmod(cf->path, filesystem_acl);

        if (result == -1) {
            cio_file_native_report_os_error();

            cio_log_error(ctx, "cannot change acl of %s to %s",
                          cf->path, ctx->options.user);

            return CIO_ERROR;
        }
    }

    return CIO_OK;
}

int cio_file_native_get_size(struct cio_file *cf, size_t *file_size)
{
    int         ret;
    struct stat st;

    ret = -1;

    if (cio_file_native_is_open(cf)) {
        ret = fstat(cf->fd, &st);
    }

    if (ret == -1) {
        ret = stat(cf->path, &st);
    }

    if (ret == -1) {
        return CIO_ERROR;
    }

    if (file_size != NULL) {
        *file_size = st.st_size;
    }

    return CIO_OK;
}

char *cio_file_native_compose_path(char *root_path, char *stream_name,
                                   char *chunk_name)
{
    size_t psize;
    char  *path;
    int    ret;

    /* Compose path for the file */
    psize = strlen(root_path) +
            strlen(stream_name) +
            strlen(chunk_name) +
            8;

    path = malloc(psize);

    if (path == NULL) {
        cio_file_native_report_runtime_error();

        return NULL;
    }

    ret = snprintf(path, psize, "%s/%s/%s",
                   root_path, stream_name, chunk_name);

    if (ret == -1) {
        cio_file_native_report_runtime_error();

        free(path);

        return NULL;
    }

    return path;
}

int cio_file_native_filename_check(char *name)
{
    size_t len;

    len = strlen(name);

    if (len == 0) {
        return CIO_ERROR;
    }
    if (len == 1) {
        if ((name[0] == '.' || name[0] == '/')) {
            return CIO_ERROR;
        }
    }

    return CIO_OK;
}

int cio_file_native_open(struct cio_file *cf)
{
    if (cio_file_native_is_open(cf)) {
        return CIO_OK;
    }

    /* Open file descriptor */
    if (cf->flags & CIO_OPEN_RW) {
        cf->fd = open(cf->path, O_RDWR | O_CREAT, (mode_t) 0600);
    }
    else if (cf->flags & CIO_OPEN_RD) {
        cf->fd = open(cf->path, O_RDONLY);
    }

    if (cf->fd == -1) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    return CIO_OK;
}

int cio_file_native_close(struct cio_file *cf)
{
    int result;

    if (cf == NULL) {
        return CIO_ERROR;
    }

    if (cio_file_native_is_open(cf)) {
        result = close(cf->fd);

        if (result == -1) {
            cio_file_native_report_os_error();

            return CIO_ERROR;
        }

        cf->fd = -1;
    }

    return CIO_OK;
}

int cio_file_native_delete_by_path(const char *path)
{
    int result;

    result = unlink(path);

    if (result == -1) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    return CIO_OK;
}

int cio_file_native_delete(struct cio_file *cf)
{
    int result;

    if (cio_file_native_is_open(cf) ||
        cio_file_native_is_mapped(cf)) {
        return CIO_ERROR;
    }

    result = unlink(cf->path);

    if (result == -1) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    return CIO_OK;
}

int cio_file_native_sync(struct cio_file *cf, int sync_mode)
{
    int result;

    if (sync_mode & CIO_FULL_SYNC) {
        sync_mode = MS_SYNC;
    }
    else {
        sync_mode = MS_ASYNC;
    }

    result = msync(cf->map, cf->alloc_size, sync_mode);

    if (result == -1) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    return CIO_OK;
}

int cio_file_native_resize(struct cio_file *cf, size_t new_size)
{
    int fallocate_available;
    int result;

    result = -1;

#if defined(CIO_HAVE_FALLOCATE) || defined(CIO_HAVE_POSIX_FALLOCATE)
    fallocate_available = CIO_TRUE;
#else
    fallocate_available = CIO_FALSE;
#endif

    /*
     * fallocate() is not portable an Linux only. Since macOS does not have
     * fallocate() we use ftruncate().
     */
    if (fallocate_available && new_size > cf->fs_size) {
        retry:

       if (cf->allocate_strategy == CIO_FILE_LINUX_FALLOCATE) {
           /*
            * To increase the file size we use fallocate() since this option
            * will send a proper ENOSPC error if the file system ran out of
            * space. ftruncate() will not fail and upon memcpy() over the
            * mmap area it will trigger a 'Bus Error' crashing the program.
            *
            * fallocate() is not portable, Linux only.
            */
#if defined(CIO_HAVE_FALLOCATE)
           result = fallocate(cf->fd, 0, 0, new_size);

#elif defined(CIO_HAVE_POSIX_FALLOCATE)
           result = -1;
           errno = EOPNOTSUPP;
#endif

           if (result == -1 && errno == EOPNOTSUPP) {
               /*
                * If fallocate fails with an EOPNOTSUPP try operation using
                * posix_fallocate. Required since some filesystems do not support
                * the fallocate operation e.g. ext3 and reiserfs.
                */
               cf->allocate_strategy = CIO_FILE_LINUX_POSIX_FALLOCATE;
               goto retry;
           }
       }
       else if (cf->allocate_strategy == CIO_FILE_LINUX_POSIX_FALLOCATE) {
#if defined(CIO_HAVE_POSIX_FALLOCATE)
            result = posix_fallocate(cf->fd, 0, new_size);
#else
            goto fallback;
#endif
       }
    }
    else
    {
#if !defined(CIO_HAVE_POSIX_FALLOCATE)
        fallback:
#endif

        result = ftruncate(cf->fd, new_size);
    }

    if (result) {
        cio_file_native_report_os_error();
    }
    else {
        cf->fs_size = new_size;
    }

    return result;
}
