/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_str.h>
#include <cfl/cfl.h>
#include <cfl/cfl_list.h>

#include <lmaccess.h>
#include <sys/stat.h>
#include <stdio.h>

/*
 * NTFS stat(2) emulation tailored for in_tail's usage.
 *
 * (1) Support st_ino (inode) for Windows NTFS.
 * (2) Support NTFS symlinks.
 * (3) Support large files >= 2GB.
 *
 * To use it, include "win32.h" and it will transparently
 * replace stat(), lstat() and fstat().
 */

#define WINDOWS_TICKS_TO_SECONDS_RATIO 10000000
#define WINDOWS_EPOCH_TO_UNIX_EPOCH_DELTA 11644473600

/*
 * FILETIME timestamps are represented in 100-nanosecond intervals,
 * because of this, that's why we need to divide the number by 10000000
 * in order to convert it to seconds.
 *
 * While UNIX timestamps use January 1, 1970 as epoch Windows FILETIME
 * timestamps use January 1, 1601. Because of this we need to subtract
 * 11644473600 seconds to account for it.
 *
 * Note: Even though this does not account for leap seconds it should be
 * accurate enough.
 */

static uint64_t filetime_to_epoch(FILETIME *ft)
{
    ULARGE_INTEGER timestamp;

    if (ft == NULL) {
        return 0;
    }

    timestamp.HighPart = ft->dwHighDateTime;
    timestamp.LowPart = ft->dwLowDateTime;

    timestamp.QuadPart /= WINDOWS_TICKS_TO_SECONDS_RATIO;
    timestamp.QuadPart -= WINDOWS_EPOCH_TO_UNIX_EPOCH_DELTA;

    return timestamp.QuadPart;
}

static void reset_errno()
{
    errno = 0;
}

static void propagate_last_error_to_errno()
{
    DWORD error_code;

    error_code = GetLastError();

    switch (error_code) {
        case ERROR_INVALID_TARGET_HANDLE:
        case ERROR_INVALID_HANDLE:
            errno = EBADF;
            break;

        case ERROR_TOO_MANY_OPEN_FILES:
            errno = EMFILE;
            break;

        case ERROR_INVALID_FLAG_NUMBER:
        case ERROR_INVALID_PARAMETER:
            errno = EINVAL;
            break;

        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_OUTOFMEMORY:
            errno = ENOMEM;
            break;

        case ERROR_SHARING_VIOLATION:
        case ERROR_LOCK_VIOLATION:
        case ERROR_PATH_BUSY:
        case ERROR_BUSY:
            errno = EBUSY;
            break;

        case ERROR_HANDLE_DISK_FULL:
        case ERROR_DISK_FULL:
            errno = ENOSPC;
            break;

        case ERROR_INVALID_ADDRESS:
            errno = EFAULT;
            break;

        case ERROR_FILE_TOO_LARGE:
            errno = EFBIG;
            break;

        case ERROR_ALREADY_EXISTS:
        case ERROR_FILE_EXISTS:
            errno = EEXIST;
            break;

        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_INVALID_DRIVE:
        case ERROR_BAD_PATHNAME:
        case ERROR_INVALID_NAME:
        case ERROR_BAD_UNIT:
            errno = ENOENT;
            break;

        case ERROR_SEEK_ON_DEVICE:
            errno = ESPIPE;
            break;

        case ERROR_NEGATIVE_SEEK:
            errno = EINVAL;
            break;

        case ERROR_ACCESS_DENIED:
            errno = EACCES;
            break;

        case ERROR_DIR_NOT_EMPTY:
            errno = ENOTEMPTY;
            break;

        case ERROR_BROKEN_PIPE:
            errno = EPIPE;
            break;

        case ERROR_GEN_FAILURE:
            errno = EIO;
            break;

        case ERROR_OPEN_FAILED:
            errno = EIO;
            break;

        case ERROR_SUCCESS:
            errno = 0;
            break;

        default:
            /* This is just a canary, if you find this
             * error then it means we need to expand the
             * translation list.
             */

            errno = EOWNERDEAD;
            break;
    }
}

static int is_symlink(const char *path)
{
    WIN32_FIND_DATA data;
    HANDLE h;

    SetLastError(0);
    reset_errno();

    h = FindFirstFileA(path, &data);

    if (h == INVALID_HANDLE_VALUE) {
        propagate_last_error_to_errno();

        return 0;
    }

    FindClose(h);

    /*
     * A NTFS symlink is a file with a bit of metadata ("reparse point"),
     * So (1) check if the file has metadata and then (2) confirm that
     * it is indeed a symlink.
     */
    if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        if (data.dwReserved0 == IO_REPARSE_TAG_SYMLINK) {
            return 1;
        }
    }

    return 0;
}

flb_file_handle flb_file_open(const char *path, unsigned int flags)
{
    DWORD  creation_disposition;
    DWORD  sharing_disposition;
    DWORD  desired_access;
    HANDLE handle;

    creation_disposition = OPEN_EXISTING;
    sharing_disposition = FILE_SHARE_READ  |
                          FILE_SHARE_WRITE |
                          FILE_SHARE_DELETE;
    desired_access = 0;

    if (flags == O_RDONLY) {
        desired_access |= FILE_READ_DATA;
    }
    else if (flags == O_WRONLY) {
        desired_access |= FILE_WRITE_DATA;
    }
    else if (flags == O_RDWR) {
        desired_access |= FILE_READ_DATA;
        desired_access |= FILE_WRITE_DATA;
    }

    if ((flags & O_APPEND) != 0) {
        desired_access |= FILE_APPEND_DATA;
    }

    if ((flags & O_CREAT) != 0) {
        if ((flags & O_EXCL) != 0) {
            creation_disposition = CREATE_NEW;
        }
        else {
            if ((flags & O_TRUNC) != 0) {
                creation_disposition = CREATE_ALWAYS;
            }
            else {
                creation_disposition = OPEN_ALWAYS;
            }
        }
    }
    else if ((flags & O_TRUNC) != 0) {
        creation_disposition = TRUNCATE_EXISTING;
    }

    handle = CreateFileA(path,
                         desired_access,
                         sharing_disposition,
                         NULL,
                         creation_disposition,
                         0,
                         NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        return FLB_FILE_INVALID_HANDLE;
    }

    return handle;
}

void flb_file_close(flb_file_handle handle)
{
    if (handle != FLB_FILE_INVALID_HANDLE) {
        CloseHandle(handle);
    }
}

ssize_t flb_file_read(flb_file_handle handle,
                      void *output_buffer,
                      size_t byte_count)
{
    DWORD bytes_read;
    DWORD result;

    bytes_read = 0;

    result = ReadFile(handle,
                      output_buffer,
                      byte_count,
                      &bytes_read,
                      NULL);

    if (result == 0) {
        propagate_last_error_to_errno();

        return -1;
    }

    return (ssize_t) bytes_read;
}

int64_t flb_file_lseek(flb_file_handle handle,
                       int64_t offset,
                       int reference_point)
{
    LONG  distance_high;
    LONG  distance_low;
    DWORD result;

    distance_high = (LONG) ((offset & 0xFFFFFFFF00000000) >> 32);
    distance_low  = (LONG) ((offset & 0x00000000FFFFFFFF));

    if (reference_point == SEEK_SET) {
        reference_point = FILE_BEGIN;
    }
    else if (reference_point == SEEK_CUR) {
        reference_point = FILE_CURRENT;
    }
    else if (reference_point == SEEK_END) {
        reference_point = FILE_END;
    }
    else {
        return -1;
    }

    result = SetFilePointer(handle,
                            distance_low,
                            &distance_high,
                            reference_point);

    if (result == INVALID_SET_FILE_POINTER) {
        propagate_last_error_to_errno();

        return -1;
    }

    offset  = (int64_t) (((uint64_t) distance_high) << 32);
    offset |= (int64_t) (((uint64_t) result));

    return offset;
}

static int flb_file_hstat(HANDLE handle,
                          struct flb_file_stat *output_buffer)
{
    FILE_STANDARD_INFO         standard_info;
    BY_HANDLE_FILE_INFORMATION handle_info;
    DWORD                      result;

    SetLastError(0);
    reset_errno();

    result = GetFileInformationByHandle(handle, &handle_info);

    if (result == 0) {
        propagate_last_error_to_errno();

        return -1;
    }

    result = GetFileInformationByHandleEx(handle,
                                          FileStandardInfo,
                                          &standard_info,
                                          sizeof(standard_info));

    if (result == 0) {
        propagate_last_error_to_errno();

        return -1;
    }

    memset(output_buffer, 0, sizeof(struct flb_file_stat));

    if (standard_info.DeletePending == 0) {
        output_buffer->hard_link_count = standard_info.NumberOfLinks;
    }
    else {
        output_buffer->hard_link_count = 0;
    }

    output_buffer->mode = 0;

    if ((handle_info.dwFileAttributes &
         FILE_ATTRIBUTE_DIRECTORY) != 0) {
        output_buffer->mode = FLB_FILE_IFDIR;
    }
    else if ((handle_info.dwFileAttributes &
              FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        output_buffer->mode = FLB_FILE_IFLNK;
    }
    else {
        output_buffer->mode = FLB_FILE_IFREG;
    }

    output_buffer->size   = (uint64_t) handle_info.nFileSizeHigh;
    output_buffer->size <<= 32;
    output_buffer->size  |= (uint64_t) handle_info.nFileSizeLow;

    output_buffer->inode   = (uint64_t) handle_info.nFileIndexHigh;
    output_buffer->inode <<= 32;
    output_buffer->inode  |= (uint64_t) handle_info.nFileIndexLow;

    output_buffer->modification_time =
        filetime_to_epoch(&handle_info.ftLastWriteTime);

    return 0;
}

int flb_file_stat(const char *path,
                  struct flb_file_stat *output_buffer)
{
    HANDLE handle;
    int    result;

    SetLastError(0);
    reset_errno();

    handle = CreateFileA(path,
                         GENERIC_READ,
                         FILE_SHARE_READ  |
                         FILE_SHARE_WRITE |
                         FILE_SHARE_DELETE,
                         NULL,
                         OPEN_EXISTING,
                         0,
                         NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        propagate_last_error_to_errno();

        return -1;
    }

    result = flb_file_hstat(handle, output_buffer);

    CloseHandle(handle);

    return result;
}

int flb_file_lstat(const char *path,
                   struct flb_file_stat *output_buffer)
{
    HANDLE handle;
    int    result;

    SetLastError(0);
    reset_errno();

    handle = CreateFileA(path,
                         GENERIC_READ,
                         FILE_SHARE_READ  |
                         FILE_SHARE_WRITE |
                         FILE_SHARE_DELETE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_FLAG_OPEN_REPARSE_POINT,
                         NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        propagate_last_error_to_errno();

        return -1;
    }

    result = flb_file_hstat(handle, output_buffer);

    CloseHandle(handle);

    if (result != 0) {
        return -1;
    }

    if (is_symlink(path)) {
        output_buffer->mode = FLB_FILE_IFLNK;
    }

    return 0;
}

int flb_file_fstat(flb_file_handle handle,
                   struct flb_file_stat *output_buffer)
{
    return flb_file_hstat(handle, output_buffer);
}

char *flb_file_get_path(flb_file_handle handle)
{
    char *buf;
    int len;

    buf = flb_calloc(sizeof(char), PATH_MAX);

    if (buf == NULL) {
        flb_errno();
        return NULL;
    }

    /* This function returns the length of the string excluding "\0"
     * and the resulting path has a "\\?\" prefix.
     */
    len = GetFinalPathNameByHandleA(handle, buf, PATH_MAX, FILE_NAME_NORMALIZED);

    if (len == 0 || len >= PATH_MAX) {
        flb_free(buf);
        return NULL;
    }

    if (strstr(buf, "\\\\?\\")) {
        memmove(buf, buf + 4, len + 1);
    }

    return buf;
}

char *flb_file_basename(const char *path)
{
    char *mutable_path;
    char *result;
    char *name;

    mutable_path = NULL;
    result = NULL;
    name = NULL;

    mutable_path = flb_strdup(path);

    if (mutable_path != NULL) {
        name = basename(mutable_path);

        if (name != NULL) {
            result = flb_strdup(name);

            if (result == NULL) {
                flb_errno();
            }
        }
        else {
            flb_errno();
        }

        flb_free(mutable_path);
    }
    else {
        flb_errno();
    }

    return result;
}


struct flb_file_glob_inner_entry {
    char           *path;
    struct cfl_list _head;
};

struct flb_file_glob_inner_context {
    struct flb_file_glob_inner_entry *current_entry;
    struct cfl_list                   results;
    size_t                            entries;
    size_t                            index;
    uint64_t                          flags;
};

static int limited_win32_glob_append_entry(
                struct flb_file_glob_inner_context *context,
                char *path,
                uint16_t mode_filter)
{
    char                              entry_path_buffer[FLB_FILE_MAX_PATH_LENGTH];
    char                             *entry_path;
    struct flb_file_stat              entry_info;
    int                               result;
    struct flb_file_glob_inner_entry *entry;

    result = flb_file_stat(path, &entry_info);

    if (result != 0) {
        result = FLB_FILE_GLOB_ERROR_NO_FILE;
    }
    else {
        result = FLB_FILE_GLOB_ERROR_SUCCESS;

        if (mode_filter != 0) {
            if (!FLB_FILE_ISTYPE(entry_info.mode, mode_filter)) {
                result = FLB_FILE_GLOB_ERROR_NO_MATCHES;
            }
        }
    }

    if (result == FLB_FILE_GLOB_ERROR_SUCCESS) {
        entry_path = _fullpath(entry_path_buffer,
                               path,
                               FLB_FILE_MAX_PATH_LENGTH);

        if (entry_path == NULL) {
            result = FLB_FILE_GLOB_ERROR_OVERSIZED_PATH;
        }
    }

    if (result == FLB_FILE_GLOB_ERROR_SUCCESS) {
        entry = flb_calloc(1, sizeof(struct flb_file_glob_inner_entry));

        if (entry == NULL) {
            return FLB_FILE_GLOB_ERROR_NO_MEMORY;
        }

        entry->path = flb_strdup(entry_path);

        if (entry->path == NULL) {
            flb_free(entry);

            return FLB_FILE_GLOB_ERROR_NO_MEMORY;
        }

        cfl_list_append(&entry->_head, &context->results);

        context->entries++;
    }

    return result;
}

/*
 * Perform patern match on the given path string. This function
 * supports patterns with "nested" wildcards like below.
 *
 *     tail_scan_pattern("C:\fluent-bit\*\*.txt", ctx);
 *
 * On success, the number of files found is returned (zero indicates
 * "no file found"). On error, -1 is returned.
 */
static int limited_win32_glob(struct flb_file_glob_inner_context *context,
                              char *path)
{
    char *star, *p0, *p1;
    char pattern[FLB_FILE_MAX_PATH_LENGTH];
    char buf[FLB_FILE_MAX_PATH_LENGTH];
    int ret;
    int n_added = 0;
    time_t now;
    int64_t mtime;
    HANDLE h;
    WIN32_FIND_DATA data;
    struct flb_file_glob_inner_entry *entry;
    int transverse_directory;
    struct flb_file_stat entry_info;

    if (strlen(path) >= FLB_FILE_MAX_PATH_LENGTH) {
        return FLB_FILE_GLOB_ERROR_OVERSIZED_PATH;
    }

    star = strchr(path, '*');

    if (star == NULL) {
        return limited_win32_glob_append_entry(context, path, 0);
    }

    /*
     * C:\data\tmp\input_*.conf
     *            0<-----|
     */
    p0 = star;
    while (path <= p0 && *p0 != '\\') {
        p0--;
    }

    /*
     * C:\data\tmp\input_*.conf
     *                   |---->1
     */
    p1 = star;
    while (*p1 && *p1 != '\\') {
        p1++;
    }

    memcpy(pattern, path, (p1 - path));
    pattern[p1 - path] = '\0';

    h = FindFirstFileA(pattern, &data);

    if (h == INVALID_HANDLE_VALUE) {
        return FLB_FILE_GLOB_ERROR_NO_MATCHES;
    }

    ret = FLB_FILE_GLOB_ERROR_SUCCESS;

    do {
        /* Ignore the current and parent dirs */
        if (!strcmp(".",  data.cFileName) ||
            !strcmp("..", data.cFileName)) {
            continue;
        }

        /* Avoid an infinite loop */
        if (strchr(data.cFileName, '*')) {
            continue;
        }

        /* Create a path (prefix + filename + suffix) */
        memcpy(buf, path, p0 - path + 1);
        buf[p0 - path + 1] = '\0';

        if ((strlen(buf) +
             strlen(data.cFileName) +
             strlen(p1)) >= FLB_FILE_MAX_PATH_LENGTH) {
            if (context->flags &
                FLB_FILE_GLOB_ABORT_ON_ERROR) {
                ret = FLB_FILE_GLOB_ERROR_OVERSIZED_PATH;

                break;
            }
            else {
                continue;
            }
        }

        strcat(buf, data.cFileName);

        if (strchr(p1, '*')) {
            transverse_directory = FLB_FALSE;

            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                transverse_directory = FLB_TRUE;
            }
            else if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                ret = flb_file_stat(data.cFileName,
                                    &entry_info);

                if (ret != 0) {
                    if (context->flags &
                        FLB_FILE_GLOB_ABORT_ON_ERROR) {
                        ret = FLB_FILE_GLOB_ERROR_NO_FILE;

                        break;
                    }
                }

                if (FLB_FILE_ISDIR(entry_info.mode)) {
                    transverse_directory = FLB_TRUE;
                }
            }

            if (transverse_directory) {
                strcat(buf, p1);

                ret = limited_win32_glob(context, buf);

                if (ret != FLB_FILE_GLOB_ERROR_SUCCESS &&
                    ret != FLB_FILE_GLOB_ERROR_NO_FILE &&
                    ret != FLB_FILE_GLOB_ERROR_NO_MATCHES) {
                    if (context->flags &
                        FLB_FILE_GLOB_ABORT_ON_ERROR) {
                        break;
                    }
                }

                continue;
            }
        }

        strcat(buf, p1);

        ret = limited_win32_glob_append_entry(context, buf, 0);

        if (ret != FLB_FILE_GLOB_ERROR_SUCCESS &&
            ret != FLB_FILE_GLOB_ERROR_NO_FILE) {
            if (context->flags &
                FLB_FILE_GLOB_ABORT_ON_ERROR) {
                break;
            }
        }

        ret = FLB_FILE_GLOB_ERROR_SUCCESS;
    } while (FindNextFileA(h, &data) != 0);

    FindClose(h);

    if (!(context->flags &
          FLB_FILE_GLOB_ABORT_ON_ERROR)) {
        ret = FLB_FILE_GLOB_ERROR_SUCCESS;
    }

    return ret;
}

int flb_file_glob_start(struct flb_file_glob_context *context,
                        const char *path,
                        uint64_t flags)
{

    int                  tilde_expansion_attempted;
    struct flb_file_stat path_stat;
    int                  result;

    if (context == NULL) {
        return -1;
    }

    memset(context, 0, sizeof(struct flb_file_glob_context));

    context->inner_context =
        flb_calloc(1, sizeof(struct flb_file_glob_inner_context));

    if (context->inner_context == NULL) {
        return -2;
    }

    cfl_list_init(&context->inner_context->results);

    context->inner_context->flags = 0;
    context->flags = flags;

    if (flags & FLB_FILE_GLOB_ABORT_ON_ERROR) {
        context->inner_context->flags |= FLB_FILE_GLOB_ABORT_ON_ERROR;
    }

    context->path = flb_strdup(path);

    if (context->path == NULL) {
        flb_file_glob_clean(context);

        return -3;
    }

    return limited_win32_glob(context->inner_context,
                              context->path);
}

void flb_file_glob_clean(struct flb_file_glob_context *context)
{
    struct cfl_list                  *iterator_backup;
    struct cfl_list                  *iterator;
    struct flb_file_glob_inner_entry *entry;

    if (context != NULL) {
        if (context->path != NULL) {
            flb_free(context->path);
        }

        if (context->inner_context != NULL) {
            cfl_list_foreach_safe(iterator,
                                  iterator_backup,
                                  &context->inner_context->results) {
                entry = cfl_list_entry(iterator,
                                       struct flb_file_glob_inner_entry,
                                       _head);

                if (entry->path != NULL) {
                    flb_free(entry->path);
                }

                cfl_list_del(&entry->_head);

                flb_free(entry);
            }

            flb_free(context->inner_context);
        }

        memset(context, 0, sizeof(struct flb_file_glob_context));
    }

}

int flb_file_glob_fetch(struct flb_file_glob_context *context,
                        char **result)
{

    if (context == NULL) {
        return FLB_FILE_GLOB_ERROR_NO_MEMORY;
    }

    if (result == NULL) {
        return FLB_FILE_GLOB_ERROR_NO_MEMORY;
    }

    *result = NULL;

    if (context->inner_context->index >=
        context->inner_context->entries) {
        return FLB_FILE_GLOB_ERROR_NO_MORE_RESULTS;
    }

    if (context->inner_context->current_entry == NULL) {
        context->inner_context->current_entry =
            cfl_list_entry_first(&context->inner_context->results,
                                 struct flb_file_glob_inner_entry,
                                 _head);
    }
    else {
        context->inner_context->current_entry =
            cfl_list_entry_next(&context->inner_context->current_entry->_head,
                                struct flb_file_glob_inner_entry,
                                _head,
                                &context->inner_context->results);
    }

    *result = context->inner_context->current_entry->path;

    context->inner_context->index++;

    return FLB_FILE_GLOB_ERROR_SUCCESS;
}
