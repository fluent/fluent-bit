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
#include <limits.h>
#include <stdio.h>

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_crc32.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_native.h>
#include <chunkio/cio_file_st.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>

int cio_file_native_unmap(struct cio_file *cf)
{
    int result;

    if (cf == NULL) {
        return CIO_ERROR;
    }

    /* Check if already unmapped first */
    if (!cio_file_native_is_mapped(cf)) {
        return CIO_OK;
    }

    /* On Windows, we can unmap even if file handle is closed */
    /* The mapping handle maintains the reference */

    result = UnmapViewOfFile(cf->map);

    if (result == 0) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    result = CloseHandle(cf->backing_mapping);

    if (result == 0) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    cf->backing_mapping = INVALID_HANDLE_VALUE;
    cf->alloc_size = 0;
    cf->map = NULL;
    cf->map_truncated_warned = CIO_FALSE;

    return CIO_OK;
}

int cio_file_native_map(struct cio_file *cf, size_t map_size)
{
    DWORD desired_protection;
    DWORD desired_access;
    size_t file_size;
    size_t actual_map_size;
    DWORD actual_map_size_high;
    DWORD actual_map_size_low;
    int ret;

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
        desired_protection = PAGE_READWRITE;
        desired_access = FILE_MAP_ALL_ACCESS;
    }
    else if (cf->flags & CIO_OPEN_RD) {
        desired_protection = PAGE_READONLY;
        desired_access = FILE_MAP_READ;
    }
    else {
        return CIO_ERROR;
    }

    /* Get current file size to ensure we don't map beyond it for read-only files */
    ret = cio_file_native_get_size(cf, &file_size);
    if (ret != CIO_OK) {
        return CIO_ERROR;
    }

    /* For read-only files, we cannot map beyond the file size */
    /* For read-write files, if map_size > file_size, we should resize first */
    if (cf->flags & CIO_OPEN_RD) {
        if (map_size > file_size) {
            actual_map_size = file_size;
        }
        else {
            actual_map_size = map_size;
        }
    }
    else {
        /* For RW files, if map_size > file_size, resize the file first */
        if (map_size > file_size) {
            ret = cio_file_native_resize(cf, map_size);
            if (ret != CIO_OK) {
                return CIO_ERROR;
            }
        }
        actual_map_size = map_size;
    }

    /* CreateFileMappingA requires size as two DWORDs (high and low) */
    /* Use actual_map_size to ensure consistency */
#if SIZE_MAX > MAXDWORD
    actual_map_size_high = (DWORD)((actual_map_size >> (sizeof(DWORD) * CHAR_BIT))
                                   & 0xFFFFFFFFUL);
    actual_map_size_low = (DWORD)(actual_map_size & 0xFFFFFFFFUL);
#else
    actual_map_size_high = 0;
    actual_map_size_low = (DWORD)actual_map_size;
#endif
    cf->backing_mapping = CreateFileMappingA(cf->backing_file, NULL,
                                             desired_protection,
                                             actual_map_size_high,
                                             actual_map_size_low,
                                             NULL);

    if (cf->backing_mapping == NULL) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    cf->map = MapViewOfFile(cf->backing_mapping, desired_access, 0, 0, actual_map_size);

    if (cf->map == NULL) {
        cio_file_native_report_os_error();

        CloseHandle(cf->backing_mapping);

        cf->backing_mapping = INVALID_HANDLE_VALUE;

        return CIO_ERROR;
    }

    cf->alloc_size = actual_map_size;

    return CIO_OK;
}

int cio_file_native_remap(struct cio_file *cf, size_t new_size)
{
    /*
     * There's no reason for this function to exist because in windows
     * we need to unmap, resize and then map again so there's no benefit
     * from remapping and I'm not implementing a dummy version because I
     * don't want anyone to read it and think there are any reasonable use
     * cases for it.
     */

    (void) cf;
    (void) new_size;

    return CIO_ERROR;
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
        cio_file_native_report_runtime_error();

        return NULL;
    }

    result = 0;
    sid_type = SidTypeUnknown;

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
                    cio_file_native_report_runtime_error();

                    free(sid_buffer);

                    return NULL;
                }
            }
            else {
                cio_file_native_report_os_error();

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

static int perform_entity_lookup(char *name,
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

int cio_file_native_lookup_user(char *user, void **result)
{
    return perform_entity_lookup(user, result, SidTypeUser);
}

int cio_file_native_lookup_group(char *group, void **result)
{
    return perform_entity_lookup(group, result, SidTypeGroup);
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

int cio_file_native_apply_acl_and_settings(struct cio_ctx *ctx, struct cio_file *cf)
{
    int result;

    if (ctx->processed_user != NULL) {
        result = cio_file_win_chown(cf->path, ctx->processed_user, ctx->processed_group);

        if (result != ERROR_SUCCESS) {
            cio_file_native_report_os_error();

            return CIO_ERROR;
        }
    }

    return CIO_OK;
}

static int get_file_size_by_handle(struct cio_file *cf, size_t *file_size)
{
    LARGE_INTEGER native_file_size;
    int           ret;

    memset(&native_file_size, 0, sizeof(native_file_size));

    ret = GetFileSizeEx(cf->backing_file, &native_file_size);

    if (ret == 0) {
        return CIO_ERROR;
    }

    if (file_size != NULL) {
        *file_size = (size_t) native_file_size.QuadPart;
    }

    return CIO_OK;
}

static int get_file_size_by_path(struct cio_file *cf, size_t *file_size)
{
    int            ret;
#ifdef _WIN64
    struct _stat64 st;
#else
    struct _stat32 st;
#endif

#ifdef _WIN64
        ret = _stat64(cf->path, &st);
#else
        ret = _stat32(cf->path, &st);
#endif

    if (ret == -1) {
        return CIO_ERROR;
    }

    if (file_size != NULL) {
        *file_size = st.st_size;
    }

    return CIO_OK;
}

int cio_file_native_get_size(struct cio_file *cf, size_t *file_size)
{
    int ret;

    ret = CIO_ERROR;

    if (cf->backing_file != INVALID_HANDLE_VALUE) {
        ret = get_file_size_by_handle(cf, file_size);
    }

    if (ret != CIO_OK) {
        ret = get_file_size_by_path(cf, file_size);
    }

    return ret;
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
            3;

    path = malloc(psize);

    if (path == NULL) {
        cio_file_native_report_runtime_error();

        return NULL;
    }

    ret = snprintf(path, psize, "%s\\%s\\%s",
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
    else if (len == 1) {
        if (name[0] == '\\' || name[0] == '.' || name[0] == '/') {
            return CIO_ERROR;
        }
    }

    return CIO_OK;
}

int cio_file_native_open(struct cio_file *cf)
{
    DWORD creation_disposition;
    DWORD desired_access;

    if (cio_file_native_is_open(cf)) {
        return CIO_OK;
    }

    if (cf->flags & CIO_OPEN) {
        desired_access = GENERIC_READ | GENERIC_WRITE;
        creation_disposition = OPEN_ALWAYS;
    }
    else if (cf->flags & CIO_OPEN_RD) {
        desired_access = GENERIC_READ;
        creation_disposition = OPEN_EXISTING;
    }
    else {
        return CIO_ERROR;
    }

    cf->backing_file = CreateFileA(cf->path,
                                   desired_access,
                                   FILE_SHARE_DELETE |
                                   FILE_SHARE_READ |
                                   FILE_SHARE_WRITE,
                                   NULL,
                                   creation_disposition,
                                   FILE_ATTRIBUTE_NORMAL,
                                   NULL);

    if (cf->backing_file == INVALID_HANDLE_VALUE) {
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
        result = CloseHandle(cf->backing_file);

        if (result == 0) {
            cio_file_native_report_os_error();

            return CIO_ERROR;
        }

        cf->backing_file = INVALID_HANDLE_VALUE;
    }

    return CIO_OK;
}

int cio_file_native_delete_by_path(const char *path)
{
    int result;

    result = DeleteFileA(path);

    if (result == 0) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    return CIO_OK;
}

int cio_file_native_delete(struct cio_file *cf)
{
    int result;

    if (cf == NULL) {
        return CIO_ERROR;
    }

    if (cio_file_native_is_mapped(cf)) {
        if (cf->ctx != NULL) {
            cio_log_warn(cf->ctx,
                         "[cio file] auto-unmapping chunk prior to delete: %s",
                         cf->path);
        }

        result = cio_file_native_unmap(cf);

        if (result != CIO_OK) {
            return result;
        }
    }

    if (cio_file_native_is_open(cf)) {
        if (cf->ctx != NULL) {
            cio_log_warn(cf->ctx,
                         "[cio file] closing handle prior to delete: %s",
                         cf->path);
        }

        result = cio_file_native_close(cf);

        if (result != CIO_OK) {
            return result;
        }
    }

    result = DeleteFileA(cf->path);

    if (result == 0) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    return CIO_OK;
}

int cio_file_native_sync(struct cio_file *cf, int sync_mode)
{
    int result;

    if (!cio_file_native_is_mapped(cf)) {
        return CIO_ERROR;
    }

    result = FlushViewOfFile(cf->map, cf->alloc_size);

    if (result == 0) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    if (sync_mode & CIO_FULL_SYNC) {
        result = FlushFileBuffers(cf->backing_file);

        if (result == 0) {
            cio_file_native_report_os_error();

            return CIO_ERROR;
        }
    }

    return CIO_OK;
}

int cio_file_native_resize(struct cio_file *cf, size_t new_size)
{
    LARGE_INTEGER movement_distance;
    int           result;

    if (!cio_file_native_is_open(cf)) {
        return CIO_ERROR;
    }

    if (cio_file_native_is_mapped(cf)) {
        return CIO_ERROR;
    }

    movement_distance.QuadPart = new_size;

    result = SetFilePointerEx(cf->backing_file,
                              movement_distance,
                              NULL, FILE_BEGIN);

    if (result == 0) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    result = SetEndOfFile(cf->backing_file);

    if (result == 0) {
        cio_file_native_report_os_error();

        return CIO_ERROR;
    }

    cf->fs_size = new_size;

    return CIO_OK;
}
