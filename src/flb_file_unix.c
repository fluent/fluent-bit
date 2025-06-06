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

#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <glob.h>
#include <pwd.h>

#ifndef GLOB_TILDE
static char *expand_tilde(const char *path,
                          int *expansion_attempted)
{
    int len;
    char user[256];
    char *p = NULL;
    char *dir = NULL;
    char *tmp = NULL;
    struct passwd *uinfo = NULL;

    if (expansion_attempted != NULL) {
        *expansion_attempted = FLB_TRUE;
    }

    if (path[0] == '~') {
        p = strchr(path, '/');

        if (p) {
            /* check case '~/' */
            if ((p - path) == 1) {
                dir = getenv("HOME");
                if (!dir) {
                    return flb_strdup(path);
                }
            }
            else {
                /*
                 * it refers to a different user: ~user/abc, first step grab
                 * the user name.
                 */
                len = (p - path) - 1;
                memcpy(user, path + 1, len);
                user[len] = '\0';

                /* use getpwnam() to resolve user information */
                uinfo = getpwnam(user);
                if (!uinfo) {
                    return flb_strdup(path);
                }

                dir = uinfo->pw_dir;
            }
        }
        else {
            dir = getenv("HOME");
            if (!dir) {
                return flb_strdup(path);
            }
        }

        if (p) {
            tmp = flb_malloc(PATH_MAX);
            if (!tmp) {
                flb_errno();
                return NULL;
            }
            snprintf(tmp, PATH_MAX - 1, "%s%s", dir, p);
        }
        else {
            dir = getenv("HOME");
            if (!dir) {
                return flb_strdup(path);
            }

            tmp = flb_strdup(dir);
            if (!tmp) {
                return flb_strdup(path);
            }
        }

        return tmp;
    }

    return flb_strdup(path);
}
#else
static char *expand_tilde(const char *path,
                          int *expansion_attempted)
{
    if (expansion_attempted != NULL) {
        *expansion_attempted = FLB_FALSE;
    }

    return flb_strdup(path);
}
#endif

static void convert_stat_buffer(struct flb_file_stat *output_buffer,
                                struct stat *input_buffer)
{
    output_buffer->device            = (uint64_t) input_buffer->st_dev;
    output_buffer->inode             = (uint64_t) input_buffer->st_ino;
    output_buffer->mode              = (uint16_t) input_buffer->st_mode;
    output_buffer->hard_link_count   = (uint16_t) input_buffer->st_nlink;
    output_buffer->size              = (uint64_t) input_buffer->st_size;

#if (defined(FLB_SYSTEM_MACOS) && !defined(_POSIX_C_SOURCE))
    output_buffer->modification_time =
        (int64_t) input_buffer->st_mtimespec.tv_sec;

#elif (defined(FLB_SYSTEM_LINUX)   || \
       defined(FLB_SYSTEM_FREEBSD) || \
       defined(FLB_SYSTEM_ANDROID) || \
       defined(FLB_SYSTEM_SOLARIS) || \
       _POSIX_C_SOURCE >= 200809L  || \
       defined(_BSD_SOURCE)        || \
       defined(_SVID_SOURCE))

    output_buffer->modification_time =
        (int64_t) input_buffer->st_mtim.tv_sec;
#else
    output_buffer->modification_time =
        (int64_t) input_buffer->st_mtime;
#endif
}

flb_file_handle flb_file_open(const char *path, unsigned int flags)
{
    return open(path, flags);
}

void flb_file_close(flb_file_handle handle)
{
    if (handle != FLB_FILE_INVALID_HANDLE) {
        close(handle);
    }
}

ssize_t flb_file_read(flb_file_handle handle,
                      void *output_buffer,
                      size_t byte_count)
{
    return read(handle, output_buffer, byte_count);
}

int64_t flb_file_lseek(flb_file_handle handle,
                       int64_t offset,
                       int reference_point)
{
    return (int64_t) lseek(handle, (off_t) offset, reference_point);
}

int flb_file_stat(const char *path,
                  struct flb_file_stat *output_buffer)
{
    struct stat stat_buffer;
    int         result;

    result = stat(path, &stat_buffer);

    if (result != -1) {
        convert_stat_buffer(output_buffer, &stat_buffer);
    }

    return result;
}

int flb_file_lstat(const char *path,
                   struct flb_file_stat *output_buffer)
{
    struct stat stat_buffer;
    int         result;

    result = lstat(path, &stat_buffer);

    if (result != -1) {
        convert_stat_buffer(output_buffer, &stat_buffer);
    }

    return result;
}

int flb_file_fstat(flb_file_handle handle,
                   struct flb_file_stat *output_buffer)
{
    struct stat stat_buffer;
    int         result;

    result = fstat(handle, &stat_buffer);

    if (result != -1) {
        convert_stat_buffer(output_buffer, &stat_buffer);
    }

    return result;
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

struct flb_file_glob_inner_context {
    glob_t   results;
    size_t   index;
    uint64_t flags;
};

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

    context->inner_context->flags = 0;
    context->flags = flags;

    if (flags & FLB_FILE_GLOB_ABORT_ON_ERROR) {
        context->inner_context->flags |= GLOB_ERR;
    }

    if (flags & FLB_FILE_GLOB_EXPAND_TILDE) {
        tilde_expansion_attempted = FLB_FALSE;

        context->path = expand_tilde(path, &tilde_expansion_attempted);

        if (tilde_expansion_attempted == FLB_FALSE) {
            context->inner_context->flags |= GLOB_TILDE;
        }
    }
    else {
        context->path = flb_strdup(path);
    }

    if (context->path == NULL) {
        flb_file_glob_clean(context);

        return -3;
    }

    result = glob(context->path,
                  context->inner_context->flags,
                  NULL,
                  &context->inner_context->results);

    if (result == GLOB_ABORTED) {
        result = FLB_FILE_GLOB_ERROR_ABORTED;
    }
    else if (result == GLOB_NOSPACE) {
        result = FLB_FILE_GLOB_ERROR_NO_MEMORY;
    }
    else if (result == GLOB_NOMATCH) {
        result = flb_file_stat(context->path, &path_stat);

        if (result == -1) {
            result = FLB_FILE_GLOB_ERROR_NO_FILE;
        }
        else {
            result = access(context->path, R_OK);

            if (result == -1 && errno == EACCES) {
                result = FLB_FILE_GLOB_ERROR_NO_ACCESS;
            }
            else {
                result = FLB_FILE_GLOB_ERROR_NO_MATCHES;
            }
        }
    }
    else {
        result = FLB_FILE_GLOB_ERROR_SUCCESS;
    }

    return result;
}

void flb_file_glob_clean(struct flb_file_glob_context *context)
{
    if (context != NULL) {
        if (context->path != NULL) {
            flb_free(context->path);
        }

        if (context->inner_context != NULL) {
            globfree(&context->inner_context->results);

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
        context->inner_context->results.gl_pathc) {
        return FLB_FILE_GLOB_ERROR_NO_MORE_RESULTS;
    }

    *result = context->inner_context->results.gl_pathv[
                context->inner_context->index];

    context->inner_context->index++;

    return FLB_FILE_GLOB_ERROR_SUCCESS;
}
