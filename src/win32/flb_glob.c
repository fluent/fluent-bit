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

#if defined(FLB_SYSTEM_WINDOWS)

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_str.h>
#include <cfl/cfl.h>
#include <cfl/cfl_list.h>
#include <fluent-bit/flb_glob_win32.h>

#include <lmaccess.h>
#include <sys/stat.h>
#include <stdio.h>

#define FLB_FILE_ISTYPE(m, t) (((m) & 0170000) == t)

static int flb_file_glob_start(struct flb_file_glob_context *context,
                               const char *path,
                               uint64_t flags);

static void flb_file_glob_clean(struct flb_file_glob_context *context);

static int flb_file_glob_fetch(struct flb_file_glob_context *context,
                               char **result);

void globfree(glob_t *context)
{
    size_t index;

    if (context->gl_pathv != NULL) {
        flb_free(context->gl_pathv);
        context->gl_pathv = NULL;
    }

    flb_file_glob_clean(&context->inner_context);
}

int glob(const char *path,
                uint64_t flags,
                void *unused,
                glob_t *context)
{
    size_t entries;
    int    result;
    size_t index;

    (void) unused;

    result = flb_file_glob_start(&context->inner_context, path, flags);

    if (result == FLB_FILE_GLOB_ERROR_SUCCESS) {
        entries = cfl_list_size(&context->inner_context.inner_context->results);

        context->gl_pathv = flb_calloc(entries, sizeof(char *));

        if (context->gl_pathv == NULL) {
            globfree(context);

            return FLB_FILE_GLOB_ERROR_NO_MEMORY;
        }

        for (index = 0 ; index < entries ; index++) {
            result = flb_file_glob_fetch(&context->inner_context,
                                         &context->gl_pathv[index]);

            if (result != FLB_FILE_GLOB_ERROR_SUCCESS) {
                globfree(context);

                return result;
            }
        }
        context->gl_pathc = entries;
    }

    return result;
}

int is_directory(char *path, struct stat *fs_entry_metadata)
{
    return ((fs_entry_metadata->st_mode & S_IFDIR) != 0);
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

static int limited_win32_glob_append_entry(
                struct flb_file_glob_inner_context *context,
                char *path,
                uint16_t mode_filter)
{
    char                              entry_path_buffer[FLB_FILE_MAX_PATH_LENGTH];
    char                             *entry_path;
    struct stat                       entry_info;
    int                               result;
    struct flb_file_glob_inner_entry *entry;

    result = stat(path, &entry_info);

    if (result != 0) {
        result = FLB_FILE_GLOB_ERROR_NO_FILE;
    }
    else {
        result = FLB_FILE_GLOB_ERROR_SUCCESS;

        if (mode_filter != 0) {
            if (!FLB_FILE_ISTYPE(entry_info.st_mode, mode_filter)) {
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
    struct stat entry_info;

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
                ret = stat(data.cFileName, &entry_info);

                if (ret != 0) {
                    if (context->flags &
                        FLB_FILE_GLOB_ABORT_ON_ERROR) {
                        ret = FLB_FILE_GLOB_ERROR_NO_FILE;

                        break;
                    }
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

static int flb_file_glob_start(struct flb_file_glob_context *context,
                               const char *path,
                               uint64_t flags)
{

    int         tilde_expansion_attempted;
    struct stat path_stat;
    int         result;

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

static void flb_file_glob_clean(struct flb_file_glob_context *context)
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

static int flb_file_glob_fetch(struct flb_file_glob_context *context,
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

#endif